from telegram import Update
from telegram.ext import ApplicationBuilder, MessageHandler, CommandHandler, filters, ContextTypes
from config import TELEGRAM_TOKEN, ALLOWED_USER_ID
from memory import conversations, process_message
import asyncio

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ALLOWED_USER_ID:
        return
    await update.message.reply_text("Good day. Arnau online.\n/clear — reset conversation")

async def cmd_clear(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ALLOWED_USER_ID:
        return
    conversations.pop(f"tg:{update.effective_user.id}", None)
    await update.message.reply_text("Conversation history cleared.")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ALLOWED_USER_ID:
        await update.message.reply_text("Unauthorized.")
        return
    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
    reply = await process_message(f"tg:{update.effective_user.id}", update.message.text)
    await update.message.reply_text(reply)

async def run():
    app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("clear", cmd_clear))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    await app.initialize()
    await app.start()
    await app.updater.start_polling(drop_pending_updates=True)
    await asyncio.Event().wait()