#!/usr/bin/env python3

__author__ = 'Matthew Schwartz (@schwartz1375)'
__version__ = '1.5'

import asyncio
import datetime
import sqlite3
from time import sleep

import aiohttp
import openai
from prettytable import PrettyTable

# Set up SQLite database
conn = sqlite3.connect('openai_cache.db')
c = conn.cursor()
# Create table if not exists
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
    print(
        f"[+] A max of {len(iat)} functions will be requested to the LLM if not cached!")

    try:
        gptable = asyncio.run(request_openai(iat))
        if gptable:
            # Pretty print the table with the result
            tabres = PrettyTable(
                ["Libraries", "API", "GPT/SQLite Cache Verdict"], align='l', max_width=60)
            for (dll_name, imp_name, gptverdict, _) in gptable:
                tabres.add_row([dll_name, imp_name, gptverdict])
            result = tabres
        else:
            result = "No data to display."

    except Exception as e:
        # Exception handling code
        result = f"An error occurred: {e}"

    return result


def extract_iat(pe):
    # Create an empty dictionary to store the IAT entries
    iat = {}

    try:
        # Retrieve the IAT entries from the PE file
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                dll_name = entry.dll.decode()  # decode to string
                # Check if imp.name is not None before decoding
                # decode to string or use "" if imp.name is None
                imp_name = imp.name.decode() if imp.name is not None else ""
                # Store the IAT entry in the dictionary
                iat[imp_name] = dll_name
    except AttributeError:
        print("The PE file does not have an import directory.")

    return iat


async def request_openai(iat):
    # Modify these to match your actual limits
    tokens_limit = 90000  # tokens per minute
    rpm_limit = 3500  # requests per minute

    async with aiohttp.ClientSession() as session:
        tasks = []
        for imp_name, dll_name in iat.items():
            # Roughly estimate the number of tokens in the request
            request_size = len(
                f"What is the purpose of this API, is there a MITRE ATT&CK technique associated and why: '{dll_name}: {imp_name}'?") / 4

            # Calculate delay based on the maximum RPM and tokens per minute limits
            delay_rpm = 60.0 / rpm_limit  # Delay in seconds based on RPM limit
            tokens_per_second = tokens_limit / 60.0  # Tokens per second
            # Delay in seconds based on tokens per minute limit
            delay_tokens = request_size / tokens_per_second

            # Use the larger delay
            delay = max(delay_rpm, delay_tokens)

            tasks.append(get_response_from_openai(imp_name, dll_name, session))
            await asyncio.sleep(delay)  # Add delay here

        gptable = await asyncio.gather(*tasks)

    return gptable


async def get_response_from_openai(imp_name, dll_name, session):
    # Open SQLite connection
    conn = sqlite3.connect('openai_cache.db')
    c = conn.cursor()

    # Check SQLite cache
    # use the LOWER function, which will convert both your input and the data in the database to lower case for comparison. This effectively makes your query case-insensitive.
    c.execute('SELECT gptverdict, inserted_at FROM openai_cache WHERE LOWER(dll_name) = LOWER(?) AND LOWER(imp_name) = LOWER(?)', (dll_name, imp_name))
    cache_result = c.fetchone()

    if cache_result is not None:
        # If result is in cache, return it
        return [dll_name, imp_name, cache_result[0], cache_result[1]]
    else:
        # If result is not in cache, query OpenAI
        prompt = f"What is the purpose of this API, is there a MITRE ATT&CK technique associated and why: '{dll_name}: {imp_name}'?"

        retry_after = 1  # initial backoff delay in seconds
        while True:
            result = await session.post(
                'http://localhost:11434/v1/chat/completions',
                headers={
                    'Content-Type': 'application/json',
                },
                json={
                    "model": "gemma", #gemma mistral llama2
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are an intelligent assistant with deep understanding of APIs and security techniques."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "max_tokens": 2500,
                    "temperature": 0.6,
                    "top_p": 1
                }
            )
            result = await result.json()
            if 'error' in result and 'Rate limit' in result['error']['message']:
                # We got rate limited, wait and then retry
                print(
                    f"Rate limit exceeded, waiting for {retry_after} seconds...")
                await asyncio.sleep(retry_after)  # Wait (backoff)
                retry_after *= 2  # Exponential backoff
                continue

            # Get current date and time
            now = datetime.datetime.now()

            if 'error' in result:
                return_val = [dll_name, imp_name,
                              result['error']['message'], now]
            else:
                try:
                    return_val = [dll_name, imp_name, result['choices']
                                  [0]['message']['content'].strip() + "\n", now]
                except Exception as e:
                    return_val = [dll_name, imp_name,
                                  f'Error in response: {str(e)}', now]

            # Check if the error is not due to rate limiting or model overload before storing the result in SQLite cache
            if not ('Rate limit' in return_val[2] or 'That model is currently overloaded' in return_val[2]):
                c.execute(
                    'INSERT INTO openai_cache VALUES (?, ?, ?, ?)', (*return_val,))
                conn.commit()

            # After processing the result, don't forget to reset retry_after
            retry_after = 1
            break

    # Close SQLite connection
    conn.close()

    return return_val
