import sys
import time
import warnings
from colorama import Fore, Style, init
from utils.api_integration import check_virustotal, check_urlscan
from utils.url_checks import perform_url_checks
from utils.email_checks import preprocess_email
from utils.model_utils import load_models, predict_with_models
warnings.filterwarnings("ignore")

google_api_key = ""

# Initialize colorama for colored terminal output
init(autoreset=True)

def display_logo():
    """Displays the ASCII art logo."""
    logo = f"""
{Fore.GREEN}██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ██╗ ██████╗ 
██╔══██╗██║  ██║██║██╔════╝██║  ██║██║████╗  ██║██╔════╝ 
██████╔╝███████║██║███████╗███████║██║██║██╔██╗ ██║██║███╗
██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║╚██╗██║██║   ██║
██║     ██║  ██║██║███████║██║  ██║██║██║ ╚████║╚██████╔╝
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
        {Fore.YELLOW}Phishing Detection System
    """
    print(logo)
    time.sleep(1)

def loading_animation(message="Loading"):
    """Displays a dynamic loading animation."""
    print(f"{Fore.CYAN}{message}", end="")
    for _ in range(3):
        time.sleep(0.5)
        print(".", end="", flush=True)
    print("\n")

def colored_print(text, color):
    """Helper function for printing colored text."""
    print(f"{color}{text}{Style.RESET_ALL}")

def display_virustotal_results(vt_result):
    """Display VirusTotal results in a formatted way."""
    colored_print("\nVirusTotal Results:", Fore.CYAN)
    
    if not vt_result.details.get("error"):
        # Display threat assessment
        threat_color = Fore.RED if vt_result.is_malicious else Fore.GREEN
        status = "Malicious" if vt_result.is_malicious else "Clean"
        colored_print(f"Status: {status}", threat_color)
        colored_print(f"Confidence Score: {vt_result.confidence}%", Fore.YELLOW)
        
        # Display detection summary
        if "detection_summary" in vt_result.details:
            colored_print("\nDetection Summary:", Fore.YELLOW)
            for category, count in vt_result.details["detection_summary"].items():
                color = Fore.RED if category == "malicious" else Fore.YELLOW
                colored_print(f"  {category.title()}: {count}", color)
        
        # Display additional details
        if "last_analysis_date" in vt_result.details:
            colored_print(f"\nLast Scan Date: {vt_result.details['last_analysis_date']}", Fore.WHITE)
        
        if "outgoing_links" in vt_result.details and vt_result.details["outgoing_links"]:
            colored_print("\nOutgoing Links:", Fore.YELLOW)
            for link in vt_result.details["outgoing_links"][:5]:  # Show first 5 links
                colored_print(f"  - {link}", Fore.WHITE)
    else:
        colored_print(f"Error: {vt_result.details['error']}", Fore.RED)

def display_urlscan_results(urlscan_result):
    """Display urlscan.io results in a formatted way."""
    colored_print("\nurlscan.io Results:", Fore.CYAN)
    
    if not urlscan_result.details.get("error"):
        colored_print("\nScan Details:", Fore.YELLOW)
        if "scan_url" in urlscan_result.details:
            colored_print(f"Results URL: {urlscan_result.details['scan_url']}", Fore.WHITE)
        if "scan_id" in urlscan_result.details:
            colored_print(f"Scan ID: {urlscan_result.details['scan_id']}", Fore.WHITE)
        if "country" in urlscan_result.details:
            colored_print(f"Server Location: {urlscan_result.details['country']}", Fore.WHITE)
        if "submission_time" in urlscan_result.details:
            colored_print(f"Submission Time: {urlscan_result.details['submission_time']}", Fore.WHITE)
    else:
        colored_print(f"Error: {urlscan_result.details['error']}", Fore.RED)

def main():
    display_logo()
    loading_animation("Initializing System")
    colored_print("Welcome to Phishing Detection System!", Fore.GREEN)
    
    while True:
        print("\nWhat would you like to check?")
        print(f"{Fore.CYAN}1. {Fore.YELLOW}URL")
        print(f"{Fore.CYAN}2. {Fore.YELLOW}Email")
        print(f"{Fore.CYAN}3. {Fore.RED}Exit")
        choice = input(f"{Fore.CYAN}Enter your choice (1/2/3): ").strip()

        if choice == "1":
            url = input(f"{Fore.CYAN}Enter the URL to check: {Fore.YELLOW}").strip()
            colored_print("\nPerforming URL checks...", Fore.BLUE)
            
            # Perform URL-specific checks
            url_check_results = perform_url_checks(url , google_api_key)
            colored_print("\nURL Checks Results:", Fore.GREEN)
            for key, value in url_check_results.items():
                colored_print(f"{key}: {value}", Fore.YELLOW)
            
            # API Checks
            colored_print("\nChecking with APIs...", Fore.BLUE)
            loading_animation("Contacting APIs")
            
            # Get and display API results
            vt_result = check_virustotal(url)
            urlscan_result = check_urlscan(url)
            
            # Display formatted results
            display_virustotal_results(vt_result)
            display_urlscan_results(urlscan_result)
            
            # Overall threat assessment
            overall_threat = "High" if vt_result.confidence > 50 else "Medium" if vt_result.confidence > 10 else "Low"
            threat_color = Fore.RED if overall_threat == "High" else Fore.YELLOW if overall_threat == "Medium" else Fore.GREEN
            
            colored_print("\nOverall Threat Assessment:", Fore.GREEN)
            colored_print(f"Threat Level: {overall_threat}", threat_color)
            
            colored_print("\nPredicting with ML Models...", Fore.BLUE)
            
            # Load models and vectorizer for URL prediction
            # In app.py, update the model loading line to:
            models, vectorizer, scaler = load_models("Url")  # Now includes scaler
            
           # For URL checks:
            predictions, probabilities = predict_with_models(models, vectorizer, url)

            colored_print("\nModel Predictions:", Fore.GREEN)
            for model_name in predictions:
                pred = predictions[model_name]
                probs = probabilities[model_name]
                result = "Phishing" if pred else "Legitimate"
                color = Fore.RED if pred else Fore.GREEN
                
                # Display prediction and probabilities
                colored_print(f"{model_name}:", Fore.CYAN)
                colored_print(f"  Prediction: {result}", color)
                if probs['legitimate'] is not None:
                    colored_print(f"  Legitimate: {probs['legitimate']}%", Fore.YELLOW)
                    colored_print(f"  Phishing: {probs['phishing']}%", Fore.YELLOW)

        elif choice == "2":
            colored_print(f"Enter the email content to check:", Fore.CYAN)
            email = sys.stdin.read().strip()
            colored_print("\nPreprocessing email...", Fore.BLUE)
            loading_animation("Analyzing Email")
            
            preprocessed_email = preprocess_email(email)
            email_content = preprocessed_email['email_content']  # Sadece e-posta içeriğini alın.
            
            colored_print("\nPredicting with ML Models...", Fore.BLUE)
            models, vectorizer, scaler = load_models("Email")
            predictions, probabilities = predict_with_models(models, vectorizer, email_content)
            
            colored_print("\nModel Predictions:", Fore.GREEN)
            for model_name, pred in predictions.items():
                pred = predictions[model_name]
                probs = probabilities[model_name]
                result = "Phishing" if pred else "Legitimate"
                color = Fore.RED if pred else Fore.GREEN
                colored_print(f"{model_name}: {result}", color)
                # Display prediction and probabilities
                colored_print(f"{model_name}:", Fore.CYAN)
                colored_print(f"  Prediction: {result}", color)
                if probs['legitimate'] is not None:
                    colored_print(f"  Legitimate: {probs['legitimate']}%", Fore.YELLOW)
                    colored_print(f"  Phishing: {probs['phishing']}%", Fore.YELLOW)

        elif choice == "3":
            colored_print("Exiting... Have a great day!", Fore.MAGENTA)
            break
        else:
            colored_print("Invalid choice. Please try again.", Fore.RED)

if __name__ == "__main__":
    main()
