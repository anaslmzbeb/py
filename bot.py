import requests
import time
import os

# Configuration
log_file_path = "~/history.log"  # <-- Change this to your actual log file path
discord_webhook_url = "https://discord.com/api/webhooks/1368789768074166433/3e3Ttm_4rQajcKK0gUTU_uZs5F8y2Oluz1NgbzzE5s45e-Kj5x_emRqNZLvfVGRBeF3T"  # <-- Replace with your actual webhook URL

def send_to_discord(message):
    payload = {
        "content": f"```{message}```"  # sends message inside a code block for formatting
    }
    try:
        response = requests.post(discord_webhook_url, json=payload)
        if response.status_code != 204:
            print(f"Discord webhook error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Exception sending to Discord: {e}")

def tail_log(file_path):
    with open(file_path, "r") as f:
        f.seek(0, os.SEEK_END)  # Go to the end of the file
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            send_to_discord(line.strip())

if __name__ == "__main__":
    if not os.path.isfile(log_file_path):
        print(f"Log file not found: {log_file_path}")
    else:
        print(f"Sending cnc.log updates to Discord webhook...")
        tail_log(log_file_path)
