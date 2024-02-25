#!/usr/bin/env python3

__author__ = 'Matthew Schwartz (@schwartz1375)'
__version__ = '1.9.5'

import asyncio
import datetime
import sqlite3
import aiohttp
from prettytable import PrettyTable
import itertools  # Import itertools for chunking dictionary

# Set up SQLite database
conn = sqlite3.connect('openai_cache.db')
c = conn.cursor()
c.execute('''
    CREATE TABLE IF NOT EXISTS openai_cache(
        dll_name TEXT,
        imp_name TEXT,
        gptverdict TEXT,
        inserted_at DATETIME,
        PRIMARY KEY(dll_name, imp_name)
    )
''')

def getOpenAiResults(pe):
    iat = extract_iat(pe)
    print(f"[+] A max of {len(iat)} functions will be requested to the LLM if not cached!")

    try:
        gptable = asyncio.run(request_openai(iat))
        if gptable:
            tabres = PrettyTable(["Libraries", "API", "GPT/SQLite Cache Verdict"], align='l', max_width=60)
            for (dll_name, imp_name, gptverdict, _) in gptable:
                tabres.add_row([dll_name, imp_name, gptverdict])
            result = tabres
        else:
            result = "No data to display."
    except Exception as e:
        result = f"An error occurred: {e}"
    return result

def extract_iat(pe):
    iat = {}
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                dll_name = entry.dll.decode()
                imp_name = imp.name.decode() if imp.name is not None else ""
                iat[imp_name] = dll_name
    except AttributeError:
        print("The PE file does not have an import directory.")
    return iat

async def request_openai(iat):
    timeout = aiohttp.ClientTimeout(total=60)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = []
        BATCH_SIZE = 10  # Adjusted to process larger batches
        iat_chunks = chunk_dict(iat, BATCH_SIZE)  # Chunk the iat dictionary
        for chunk in iat_chunks:
            tasks.append(process_batch(chunk, session))
        
        gptable = await asyncio.gather(*tasks)
        return [item for sublist in gptable for item in sublist]

def chunk_dict(data, chunk_size):
    """Yield successive chunk_size chunks from data."""
    it = iter(data)
    for _ in range(0, len(data), chunk_size):
        yield {k: data[k] for k in itertools.islice(it, chunk_size)}

async def process_batch(batch, session):
    batch_result = []
    for imp_name, dll_name in batch.items():
        result = await get_response_from_openai(imp_name, dll_name, session)
        batch_result.append(result)
        await asyncio.sleep(0.1)  # Slight delay to prevent rate limit issues
    return batch_result

async def get_response_from_openai(imp_name, dll_name, session):
    conn = sqlite3.connect('openai_cache.db')
    c = conn.cursor()
    c.execute('SELECT gptverdict, inserted_at FROM openai_cache WHERE LOWER(dll_name) = LOWER(?) AND LOWER(imp_name) = LOWER(?)', (dll_name, imp_name))
    cache_result = c.fetchone()

    if cache_result:
        return [dll_name, imp_name, cache_result[0], cache_result[1]]
    else:
        prompt = f"What is the purpose of this API, is there a MITRE ATT&CK technique associated and why: '{dll_name}: {imp_name}'?"
        retry_after = 1
        for attempt in range(5):  # Retry up to 5 times
            try:
                response = await session.post(
                    'http://localhost:11434/v1/chat/completions',
                    headers={'Content-Type': 'application/json'},
                    json={
                        "model": "gemma",
                        "messages": [
                            {"role": "system", "content": "You are an intelligent assistant with deep understanding of APIs and security techniques."},
                            {"role": "user", "content": prompt}
                        ],
                        "max_tokens": 2000,
                        "temperature": 0.6,
                        "top_p": 1
                    },
                    timeout=60
                )
                result = await response.json()
                now = datetime.datetime.now()
                if 'error' not in result:
                    gpt_verdict = result['choices'][0]['message']['content'].strip() + "\n"
                    c.execute('INSERT INTO openai_cache VALUES (?, ?, ?, ?)', (dll_name, imp_name, gpt_verdict, now))
                    conn.commit()
                    return [dll_name, imp_name, gpt_verdict, now]
            except asyncio.TimeoutError:
                print(f"Request timed out, retrying in {retry_after} seconds...")
                await asyncio.sleep(retry_after)
                retry_after *= 2  # Exponential backoff
        return [dll_name, imp_name, "Request failed after retries", datetime.datetime.now()]

if __name__ == "__main__":
    pe = {}  # Placeholder for PE object
    print(getOpenAiResults(pe))
