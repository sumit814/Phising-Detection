import unittest
from unittest.mock import patch
from core.analyzer import URLAnalyzer
import socket
import ssl

class TestURLAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = URLAnalyzer()
        self.legit_url = "https://google.com"
        self.suspicious_url = "http://paypal-security-update.tk"
        self.ip_url = "http://192.168.1.1/login"
        self.typo_url = "https://g00gle.com"
        self.homograph_url = "https://аррӏе.com"  # Cyrillic
        self.encoded_url = "https://example.com/%20test"
        self.long_subdomain_url = "https://sub1.sub2.sub3.sub4.google.com"

    def tearDown(self):
        pass

    def test_basic_checks_legitimate(self):
        """Test legitimate URL characteristics"""
        result = self.analyzer.analyze(self.legit_url)
        basic = result['basic']
        
        self.assertFalse(basic['has_ip'])
        self.assertTrue(basic['has_https'])
        self.assertFalse(basic['shortened'])
        self.assertFalse(basic['suspicious_tld'])
        self.assertFalse(basic['many_hyphens'])
        self.assertFalse(basic['is_encoded'])
        self.assertLess(basic['many_subdomains'], 3)

    def test_basic_checks_suspicious(self):
        """Test suspicious URL characteristics"""
        result = self.analyzer.analyze(self.suspicious_url)
        basic = result['basic']
        
        self.assertTrue(basic['suspicious_tld'])
        self.assertFalse(basic['has_https'])
        self.assertGreater(basic['many_hyphens'], 3)

    def test_ip_address_url(self):
        """Test URL with direct IP address"""
        result = self.analyzer.analyze(self.ip_url)
        self.assertTrue(result['basic']['has_ip'])

    def test_typosquatting_detection(self):
        """Test typosquatting detection"""
        result = self.analyzer.analyze(self.typo_url)
        self.assertTrue(result['advanced']['typosquatting'])

    def test_homograph_detection(self):
        """Test homograph attack detection"""
        result = self.analyzer.analyze(self.homograph_url)
        self.assertTrue(result['advanced']['homograph'])

    def test_encoded_url(self):
        """Test URL encoding detection"""
        result = self.analyzer.analyze(self.encoded_url)
        self.assertTrue(result['basic']['is_encoded'])

    def test_subdomain_count(self):
        """Test excessive subdomain detection"""
        result = self.analyzer.analyze(self.long_subdomain_url)
        self.assertTrue(result['basic']['many_subdomains'])

    @patch('ssl.create_default_context')
    @patch('socket.create_connection')
    def test_ssl_validation(self, mock_socket, mock_ssl):
        """Test SSL certificate validation with mock"""
        # Configure mock SSL response
        mock_ssl.return_value.wrap_socket.return_value.getpeercert.return_value = {
            'notAfter': 'Jan 01 23:59:59 2030 GMT'
        }
        
        result = self.analyzer.analyze("https://valid-ssl.com")
        self.assertTrue(result['security']['ssl_valid'])

        # Test expired certificate
        mock_ssl.return_value.wrap_socket.return_value.getpeercert.return_value = {
            'notAfter': 'Jan 01 23:59:59 2000 GMT'
        }
        result = self.analyzer.analyze("https://expired-ssl.com")
        self.assertFalse(result['security']['ssl_valid'])

    def test_entropy_calculation(self):
        """Test entropy calculation for different strings"""
        low_entropy = "google"
        high_entropy = "xJ8#k!3p"
        
        self.assertLess(self.analyzer._calculate_entropy(low_entropy), 2.5)
        self.assertGreater(self.analyzer._calculate_entropy(high_entropy), 3.5)

    def test_levenshtein_distance(self):
        """Test Levenshtein distance calculation"""
        self.assertEqual(self.analyzer._levenshtein("kitten", "sitting"), 3)
        self.assertEqual(self.analyzer._levenshtein("google", "g00gle"), 2)
        self.assertEqual(self.analyzer._levenshtein("", "test"), 4)

    def test_domain_analysis_metrics(self):
        """Test domain analysis metrics"""
        result = self.analyzer.analyze("https://test123-domain.com")
        domain = result['domain']
        
        self.assertEqual(domain['length'], len("test123-domain.com"))
        self.assertGreater(domain['digit_ratio'], 0.1)
        self.assertGreater(domain['symbol_ratio'], 0.05)

if __name__ == "__main__":
    unittest.main(failfast=True)
