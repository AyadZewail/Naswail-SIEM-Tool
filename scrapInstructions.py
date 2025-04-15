import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import quote_plus, urlparse
import logging
import time
import argparse
from sentence_transformers import SentenceTransformer, util
import spacy
import torch
import pandas as pd
import numpy as np
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

parser = argparse.ArgumentParser(description="Scrape search results for a given query.")
parser.add_argument("query", type=str, help="Search query for scraping")
args = parser.parse_args()
search_query = args.query  # Store query
model = SentenceTransformer('all-MiniLM-L6-v2')
nlp = spacy.load("en_core_web_sm", disable=["parser", "ner"])
nlp.add_pipe("sentencizer")
mit_emb_file = "mitigation_embeddings.pt"

# Constants
BING_SEARCH_URL = "https://www.bing.com/search"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
HEADERS = {"User-Agent": USER_AGENT}
MAX_CONCURRENT_REQUESTS = 5
TIMEOUT = aiohttp.ClientTimeout(total=10)
BLACKLIST = ["bing.com", "go.microsoft.com", "microsoft.com/en-us", "support.microsoft.com"]
selenium_driver = None

def clean_url(url):
    """Clean and validate URLs from search results"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url.split('&')[0]  # Remove tracking parameters

def init_selenium_driver():
    global selenium_driver
    if selenium_driver is None:
        options = Options()
        options.add_argument("--headless=new")  
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--log-level=3")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-notifications")
        options.add_argument("--disable-application-cache")
        options.add_argument("--disable-logging")  # Suppress DevTools logs
        options.add_argument("--output=/dev/null")  # Silence console output (Linux/Mac)
        options.add_argument("--disk-cache-size=0")
        options.add_argument("--disable-features=DiskCache")
        options.add_argument("--blink-settings=imagesEnabled=false")  # Disable images
        options.add_argument("--dns-prefetch-disable")
        options.add_argument("--disable-popup-blocking")
        options.add_argument("--disable-component-update")
        prefs = {"profile.managed_default_content_settings.images": 2}
        options.add_experimental_option("prefs", prefs)
        options.add_experimental_option('excludeSwitches', ['enable-logging'])
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        options.add_argument(f"user-agent={user_agent}")
        options.page_load_strategy = "eager"
        selenium_driver = webdriver.Chrome(options=options)
        selenium_driver.set_page_load_timeout(8)
        logger.info("Initialized Selenium driver")

def scrape_bing_with_selenium(keyword):
    init_selenium_driver()
    selenium_driver.get(f"{BING_SEARCH_URL}?q={keyword}")
    elements = selenium_driver.find_elements(By.CSS_SELECTOR, "li.b_algo h2 a")
    urls = []
    for el in elements:
        href = el.get_attribute("href")
        if href and href.startswith("http") and not any(b in href for b in BLACKLIST):
            clean_href = clean_url(href)
            if clean_href not in urls:
                urls.append(clean_href)
    logger.info(f"Selenium found {len(urls)} search results")
    return urls

async def scrape_bing_results(keyword):
    urls = []
    try:
        async with aiohttp.ClientSession(headers=HEADERS, timeout=TIMEOUT) as session:
            async with session.get(f"{BING_SEARCH_URL}?q={keyword}") as response:
                response.raise_for_status()
                html = await response.text()
                # Parse the search results page
                soup = BeautifulSoup(html, 'html.parser')
                
                # Find all result links - Bing's current structure
                for a in soup.select('h2 a'):
                    href = a.get('href')
                    if href.startswith('http') and not any(blocked in href for blocked in BLACKLIST):
                        clean_href = clean_url(href)
                        if clean_href not in urls:
                            urls.append(clean_href)
                
        if urls:
            logger.info(f"Found {len(urls)} search results")
            return urls
            
        logger.warning("No results from aiohttp. Falling back to Selenium.")
        selenium_urls = await asyncio.to_thread(scrape_bing_with_selenium, keyword)
        return selenium_urls
                
    except Exception as e:
        logger.error(f"Error scraping Bing results: {e}")
        return []

async def extract_text(session, link):
    """Extract text content from a URL"""
    try:
        async with session.get(link, headers=HEADERS, timeout=TIMEOUT) as response:
            if response.status == 200:
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' not in content_type:
                    return link, ""
                
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                paragraphs = soup.find_all('p')
                text = "\n".join([p.get_text(strip=True) for p in paragraphs if p.get_text(strip=True)])
                return link, text if len(text) > 200 else None
    except Exception as e:
        print(f"Error processing {link}: {e}")
        return None

async def process_urls(urls):
    """Process multiple URLs with rate limiting"""
    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT_REQUESTS)
    async with aiohttp.ClientSession(
        headers=HEADERS,
        timeout=TIMEOUT,
        connector=connector
    ) as session:
        tasks = [extract_text(session, url) for url in urls]
        results = await asyncio.gather(*tasks)
        return [result for result in results if result is not None]

def is_valid(url):
    """Validate URLs"""
    return url.startswith(('http://', 'https://')) and \
        not any(ext in url.lower() for ext in ('.pdf', '.jpg', '.png', '.doc', '.ppt')) and \
        not url.startswith('mailto:')

def save_to_csv(data):
    """Save results to CSV"""
    df = pd.DataFrame(data, columns=["URL", "Extracted Text"])
    df.to_csv("output.csv", index=False)

def get_mitigation():
    """Extract mitigation strategies from results"""
    try:
        mitigation_embeddings = torch.load(mit_emb_file, map_location='cpu')
    except FileNotFoundError:
        with open("mit_refs.txt", "r") as f:
            mitigation_refs = [line.strip() for line in f.readlines()]
        mitigation_embeddings = model.encode(mitigation_refs, convert_to_tensor=True)
        torch.save(mitigation_embeddings, mit_emb_file,
               _use_new_zipfile_serialization=False)

    data = pd.read_csv("output.csv")
    docs = data["Extracted Text"].tolist()

    docs = list(nlp.pipe(docs, batch_size=256))
    sentences = [sent.text.strip() for doc in docs for sent in doc.sents]

    mitigation_sentence, score = extract_mitigation_sentences(sentences, mitigation_embeddings)
    return mitigation_sentence, score

action_verbs = {"block", "reject", "disable", "enable", "apply", "restrict", "update", "deploy", "terminate", "implement"}
tech_terms = {"port", "protocol", "CVE", "patch", "firewall", "whitelisting"}

action_lemmas = {token.lemma_.lower() for token in nlp(" ".join(action_verbs))}
tech_lemmas = {token.lemma_.lower() for token in nlp(" ".join(tech_terms))}

def extract_mitigation_sentences(sentences, mitigation_embeddings):
    """Extract relevant mitigation sentences"""
    if not sentences:
        return "No Sentences Retrieved", 0.0
    
    embeddings = model.encode(sentences, convert_to_tensor=True)
    scores = util.pytorch_cos_sim(embeddings, mitigation_embeddings).max(dim=1)[0]
    
    mask = scores > 0.2
    filtered_sentences = [sentences[i] for i in np.where(mask)[0]]
    filtered_scores = scores[mask]

    docs = list(nlp.pipe(filtered_sentences, batch_size=64))
    
    filtered = []
    for sent, score, doc in zip(filtered_sentences, filtered_scores, docs):
        sent_lemmas = {token.lemma_.lower() for token in doc}
        has_action = not action_lemmas.isdisjoint(sent_lemmas)
        has_tech = not tech_lemmas.isdisjoint(sent_lemmas)
        final_score = score + 0.3 if (has_action and has_tech) else score
        filtered.append((sent, final_score))

    if not filtered:
        filtered = list(zip(filtered_sentences, filtered_scores))

    sorted_sentences = sorted(filtered, key=lambda x: x[1].item(), reverse=True)
    top_entries = sorted_sentences[:10]
    
    top_sentences = [sent for sent, _ in top_entries]
    avg_score = torch.mean(torch.stack([s for _, s in top_entries])) if top_entries else 0.0
    
    return ' '.join(top_sentences), avg_score.item()

async def main():
    start_time = time.time()

    logger.info(f"Searching Bing for: {search_query}")
    links = await scrape_bing_results(search_query)
    end_time = time.time()
    print(f"##########################\nScrape Runtime: {end_time - start_time:.2f} seconds\n")
    
    if not links:
        logger.error("No search results found or error occurred.")
        return

    print(f"Extracting content from {len(links)} pages...")
    results = await process_urls(links)
    
    # Display results
    print("\n=== Results ===")
    for url, paragraphs in results:
        print(f"URL: {url}")
    
    # Filter out empty results
    extracted_data = [(url, text) for url, text in results if text]
    save_to_csv(extracted_data)
    end_time = time.time()
    print(f"##########################\nFile Proccessing Runtime: {end_time - start_time:.2f} seconds\n")
    
    # Step 3: Analyze for mitigation strategies
    print("Analyzing content for mitigation strategies...")
    mitigation_sentence, score = get_mitigation()
    
    # Output results
    end_time = time.time()
    print(f"\n Total Runtime: {end_time - start_time:.2f} seconds")
    print(f"\nRelevance Score: {score:.2f}")
    print("\nExtracted Mitigation Strategy:")
    print(mitigation_sentence)

if __name__ == "__main__":
    asyncio.run(main())
