from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import requests
import concurrent.futures
import contextlib
import time
import argparse
import csv
import pandas as pd
import torch
from sentence_transformers import SentenceTransformer, util
import spacy
import numpy as np
import os

start_time = time.time()

parser = argparse.ArgumentParser(description="Scrape search results for a given query.")
parser.add_argument("query", type=str, help="Search query for scraping")
args = parser.parse_args()
search_query = args.query  # Store query
model = SentenceTransformer('all-MiniLM-L6-v2')
nlp = spacy.load("en_core_web_sm", disable=["parser", "ner"])
nlp.add_pipe("sentencizer")
mit_emb_file = "mitigation_embeddings.pt"

def extract_text(link):
    if link.endswith(".pdf"):  
        return f"Skipping PDF: {link}", link

    # Try requests + BeautifulSoup first
    try:
        response = requests.get(link, headers={"User-Agent": "Mozilla/5.0"}, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            paragraphs = soup.find_all("p")
            text = "\n".join([p.get_text(strip=True) for p in paragraphs if p.get_text(strip=True)])
            
            if len(text) > 200:  # If enough text is extracted, return it
                return text, link
    except requests.exceptions.RequestException:
        pass  # If request fails, fallback to Selenium

    # Selenium fallback for JavaScript-heavy sites
    try:
        local_driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        local_driver.get(link)
        WebDriverWait(local_driver, 5).until(EC.presence_of_element_located((By.TAG_NAME, "p")))

        paragraphs = local_driver.find_elements(By.TAG_NAME, "p")
        text = "\n".join([p.text for p in paragraphs if p.text.strip()])

        local_driver.quit()
        return link, text

    except Exception as e:
        return f"Skipping {link} due to error: {e}", link

def save_to_csv(data):
    with open("output.csv", "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["URL", "Extracted Text"])  # Header
        writer.writerows(data)

def getMitigation():
    try:
        mitigation_embeddings = torch.load(mit_emb_file, map_location='cpu')
    except FileNotFoundError:
        with open("mit_refs.txt", "r") as f:
            mitigation_refs = [line.strip() for line in f.readlines()]
        mitigation_embeddings = model.encode(mitigation_refs, convert_to_tensor=True)
        torch.save(mitigation_embeddings, mit_emb_file,
               _use_new_zipfile_serialization=False)  # Save for future use

    data = pd.read_csv("output.csv")
    docs = data["Extracted Text"].tolist()

    docs = list(nlp.pipe(docs, batch_size=64))  # Batch processing
    sentences = [sent.text.strip() for doc in docs for sent in doc.sents]

    mitigation_sentence, score = extract_mitigation_sentences(sentences, mitigation_embeddings)

    return mitigation_sentence, score

action_verbs = {"block", "reject", "disable", "enable", "apply", "restrict", "update", "deploy", "terminate", "implement"}
tech_terms = {"port", "protocol", "CVE", "patch", "firewall", "whitelisting"}

# Preprocess lemma sets using spaCy (do this once at startup)
action_lemmas = {token.lemma_.lower() for token in nlp(" ".join(action_verbs))}
tech_lemmas = {token.lemma_.lower() for token in nlp(" ".join(tech_terms))}

def extract_mitigation_sentences(sentences, mitigation_embeddings):
    embeddings = model.encode(sentences, convert_to_tensor=True)
    scores = util.pytorch_cos_sim(embeddings, mitigation_embeddings).max(dim=1)[0]
    
    # Filter by similarity score
    mask = scores > 0.2
    filtered_sentences = [sentences[i] for i in np.where(mask)[0]]
    filtered_scores = scores[mask]

    # Batch process all filtered sentences with spaCy
    docs = list(nlp.pipe(filtered_sentences, batch_size=64))
    
    # Vectorized filtering using set operations
    filtered = []
    for sent, score, doc in zip(filtered_sentences, filtered_scores, docs):
        sent_lemmas = {token.lemma_.lower() for token in doc}
        
        # Check for intersections using set operations
        has_action = not action_lemmas.isdisjoint(sent_lemmas)
        has_tech = not tech_lemmas.isdisjoint(sent_lemmas)
        
        if has_action and has_tech:
            final_score = score + 0.3
        else:
            final_score = score
        
        filtered.append((sent, final_score))

    # Fallback to similarity-filtered results
    if not filtered:
        filtered = list(zip(filtered_sentences, filtered_scores))

    # Sort and select top entries
    sorted_sentences = sorted(filtered, key=lambda x: x[1].item(), reverse=True)
    top_entries = sorted_sentences[:10]
    
    # Prepare results
    top_sentences = [sent for sent, _ in top_entries]
    avg_score = torch.mean(torch.stack([s for _, s in top_entries])) if top_entries else 0.0
    
    return ' '.join(top_sentences), avg_score.item()

def is_valid(url):
    return not any(ext in url for ext in ('.pdf', '.jpg', '.png')) and \
           not url.startswith('mailto:')

# Configure Selenium
options = Options()
options.add_argument("--headless=new")  
options.add_argument("--disable-gpu")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")
options.add_argument("--disable-background-timer-throttling")
options.add_argument("--disable-backgrounding-occluded-windows")
options.add_argument("--disable-renderer-backgrounding")
options.add_argument("--log-level=3")
options.page_load_strategy = "eager"

service = Service(ChromeDriverManager().install())

# Start Selenium WebDriver
driver = webdriver.Chrome(service=service, options=options)
driver.set_page_load_timeout(8)  # Avoids long wait times

# Perform Search
driver.get(f"https://www.bing.com/search?q={search_query.replace(' ', '+')}")

extracted_data = []

try:
    WebDriverWait(driver, 5).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, "li.b_algo h2 a"))
    )

    # Extract links
    results = driver.find_elements(By.CSS_SELECTOR, "li.b_algo h2 a")
    links = [r.get_attribute("href") for r in results if r.get_attribute("href")]
    if not links:
        print("❌ No links found in search results!")
        exit(1)
    links = [link for link in links if is_valid(link)]

    driver.quit()  # Close WebDriver after fetching links

    workers = min(8, (os.cpu_count() or 1) * 2)  # Optimal worker count

    with contextlib.suppress(TypeError):
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            results = executor.map(extract_text, links)

    for text, url in results:  
        extracted_data.append((url, text))

except Exception as e:
    print("Error during search:", e)

save_to_csv(extracted_data)  # Save results

mitigation_sentence, score = getMitigation()
end_time = time.time()
print(f"##########################\nTotal Runtime: {end_time - start_time:.2f} seconds\n")
print("\nExtracted Mitigation Strategy:")
print(mitigation_sentence)