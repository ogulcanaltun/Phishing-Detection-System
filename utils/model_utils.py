from joblib import load
import os
import numpy as np
from urllib.parse import urlparse
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer

def extract_url_features(url):
    """
    Extracts features from a URL for prediction.
    Returns both numerical features and the raw URL for text vectorization.
    """
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path_length = len(parsed_url.path)
    url_length = len(url)
    num_subdomains = domain.count('.')
    contains_login = 1 if "login" in url.lower() else 0
    
    # Create numerical features array
    numerical_features = np.array([
        path_length,
        url_length,
        num_subdomains,
        contains_login
    ]).reshape(1, -1)
    
    return numerical_features, url

def load_models(folder_path):
    """
    Loads the machine learning models, vectorizer, and scaler from the specified folder.
    """
    models = {}
    vectorizer = None
    scaler = None
    
    for filename in os.listdir(folder_path):
        if filename.endswith("_model.pkl"):
            model_name = filename.split("_model.pkl")[0]
            models[model_name] = load(os.path.join(folder_path, filename))
        elif filename == "vectorizer.pkl":
            vectorizer = load(os.path.join(folder_path, filename))
        elif filename == "scaler.pkl":
            scaler = load(os.path.join(folder_path, filename))
    
    if vectorizer is None:
        vectorizer = TfidfVectorizer()
    if scaler is None:
        scaler = StandardScaler()
    
    return models, vectorizer, scaler

def predict_with_models(models, vectorizer, text):
    """
    Preprocess and predict using the given models and vectorizer.
    Returns both predictions and probabilities for each model.
    """
    predictions = {}
    probabilities = {}

    if isinstance(text, str) and (text.startswith('http') or text.startswith('https')):
        # Extract URL features and get the raw URL for vectorization
        numerical_features, raw_url = extract_url_features(text)
        
        # Vectorize the URL text
        text_features = vectorizer.transform([raw_url]).toarray()
        
        # Scale numerical features
        scaler = StandardScaler()
        scaled_numerical = scaler.fit_transform(numerical_features)
        
        # Combine features while maintaining the expected dimensionality
        combined_features = np.concatenate([
            text_features[:, :10],  # Take first 10 text features
            scaled_numerical.reshape(1, -4)  # Add 4 numerical features
        ], axis=1)
        
    else:
        # For email content, just use the vectorizer
        combined_features = vectorizer.transform([text]).toarray()
        combined_features = combined_features[:, :4999]  # Drop the last feature


    # Make predictions and get probabilities for each model
    for model_name, model in models.items():
        try:
            predictions[model_name] = model.predict(combined_features)[0]
            # Get probability scores if the model supports predict_proba
            if hasattr(model, 'predict_proba'):
                probs = model.predict_proba(combined_features)[0]
                probabilities[model_name] = {
                    'legitimate': round(probs[0] * 100, 2),
                    'phishing': round(probs[1] * 100, 2)
                }
            else:
                # For models that don't support probabilities, use decision_function if available
                if hasattr(model, 'decision_function'):
                    decision_score = model.decision_function(combined_features)[0]
                    # Convert decision score to a probability-like score
                    prob_score = 1 / (1 + np.exp(-decision_score))
                    probabilities[model_name] = {
                        'legitimate': round((1 - prob_score) * 100, 2),
                        'phishing': round(prob_score * 100, 2)
                    }
                else:
                    probabilities[model_name] = {
                        'legitimate': None,
                        'phishing': None
                    }
        except ValueError as e:
            print(f"Error predicting with {model_name}: {str(e)}")
            predictions[model_name] = None
            probabilities[model_name] = {'legitimate': None, 'phishing': None}

    return predictions, probabilities