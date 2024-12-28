import re
from colorama import Fore

def preprocess_email(email_content):
    """
    Preprocess the email content for machine learning models.
    This includes extracting relevant features like links, suspicious keywords, etc.
    
    Args:
        email_content (str): The email body content.
    
    Returns:
        dict: A dictionary of preprocessed features for ML models.
    """
    print(f"{Fore.CYAN}Preprocessing email content...")
    
    # Feature: Extract URLs
    urls = re.findall(r'https?://\S+|www\.\S+', email_content)
    num_urls = len(urls)
    print(f"{Fore.YELLOW}Number of URLs detected: {num_urls}")
    
    # Feature: Detect suspicious keywords
    suspicious_keywords = ['login', 'update', 'verify', 'account', 'password', 'secure']
    num_suspicious_keywords = sum(keyword in email_content.lower() for keyword in suspicious_keywords)
    print(f"{Fore.YELLOW}Number of suspicious keywords detected: {num_suspicious_keywords}")
    
    # Feature: Check for IP addresses
    ip_addresses = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', email_content)
    num_ip_addresses = len(ip_addresses)
    print(f"{Fore.YELLOW}Number of IP addresses detected: {num_ip_addresses}")
    
    # Feature: Count total words
    total_words = len(email_content.split())
    print(f"{Fore.YELLOW}Total words in the email: {total_words}")
    
    # Combine features into a feature vector
    feature_vector = {
        'num_urls': num_urls,
        'num_suspicious_keywords': num_suspicious_keywords,
        'num_ip_addresses': num_ip_addresses,
        'total_words': total_words,
        'email_content': email_content
    }
    
    print(f"{Fore.CYAN}Preprocessing complete!")
    return feature_vector
