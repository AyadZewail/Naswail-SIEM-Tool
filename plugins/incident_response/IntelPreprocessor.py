# ir/components/simple_intel_preprocessor.py
import torch
import numpy as np
import pandas as pd
import spacy
from sentence_transformers import SentenceTransformer, util

from plugins.incident_response.interfaces import IIntelPreprocessor

class SimpleIntelPreprocessor(IIntelPreprocessor):
    def __init__(self):
        self.mit_emb_file = "data/mitigation_embeddings.pt"
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.nlp = spacy.load("en_core_web_sm", disable=["parser", "ner"])
        self.nlp.add_pipe("sentencizer")
        self.key_words = {"block", "blocking", "reject", "disable", "restrict", "terminate", "limit", "limiting", "rate", "rate-limiting"}
        self.key_lemmas = {token.lemma_.lower() for token in self.nlp(" ".join(self.key_words))}

    def load_embeddings(self):
        try:
            return torch.load(self.mit_emb_file, map_location='cpu')
        except FileNotFoundError:
            with open("data/mit_refs.txt", "r") as f:
                mitigation_refs = [line.strip() for line in f.readlines()]
            mitigation_embeddings = self.model.encode(mitigation_refs, convert_to_tensor=True)
            torch.save(mitigation_embeddings, self.mit_emb_file, _use_new_zipfile_serialization=False)
            return mitigation_embeddings

    def extract_mitigation_sentences(self, sentences, mitigation_embeddings):
        if not sentences:
            return "No sentences were retrieved", 0.0

        embeddings = self.model.encode(sentences, convert_to_tensor=True)
        scores = util.pytorch_cos_sim(embeddings, mitigation_embeddings).max(dim=1)[0]

        mask = scores > 0.7
        filtered_sentences = [sentences[i] for i in np.where(mask)[0]]
        filtered_scores = scores[mask]

        docs = list(self.nlp.pipe(filtered_sentences, batch_size=64))
        filtered = []
        for sent, score, doc in zip(filtered_sentences, filtered_scores, docs):
            sent_lemmas = {token.lemma_.lower() for token in doc}
            has_key = not self.key_lemmas.isdisjoint(sent_lemmas)
            final_score = score + 0.2 if has_key else score
            filtered.append((sent, final_score))

        if not filtered:
            filtered = list(zip(filtered_sentences, filtered_scores))

        sorted_sentences = sorted(filtered, key=lambda x: x[1].item() if hasattr(x[1], 'item') else x[1], reverse=True)
        top_entries = sorted_sentences[:1]
        top_sentences = [sent for sent, _ in top_entries]
        avg_score = torch.mean(torch.stack([s for _, s in top_entries])) if top_entries else 0.0
        return ' '.join(top_sentences), avg_score.item() if hasattr(avg_score, 'item') else avg_score

    def preprocess(self, input_dict: dict) -> dict:
        data = input_dict.get("data", [])
        docs = list(self.nlp.pipe(data, batch_size=256))
        sentences = [sent.text.strip() for doc in docs for sent in doc.sents]
        mit_emb = self.load_embeddings()
        mitigation_sentence, score = self.extract_mitigation_sentences(sentences, mit_emb)

        return {
            "mitigation": mitigation_sentence,
            "score": score
        }