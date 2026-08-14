from app import config, telegram

url = f"{config.APP_BASE_URL}/api/telegram/webhook"
result = telegram.set_webhook(url)
print("setWebhook ->", result)