from colorama import Fore, Style
import logging

class DecryptXFormatter(logging.Formatter):

    FORMATS = {
        logging.DEBUG: f"{Fore.CYAN}🐾 DEBUG: {Style.RESET_ALL}%(message)s",
        logging.INFO: f"{Fore.GREEN}💡 INFO: {Style.RESET_ALL}%(message)s",
        logging.WARNING: f"{Fore.YELLOW}⚠️ WARNING: {Style.RESET_ALL}%(message)s",
        logging.ERROR: f"{Fore.RED}❌ ERROR: {Style.RESET_ALL}%(message)s",
        logging.CRITICAL: f"{Fore.MAGENTA}🔥 CRITICAL: {Style.RESET_ALL}%(message)s"
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, "%(message)s")
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

logging.basicConfig(level=logging.INFO)
decryptXLogger = logging.getLogger()

handler = logging.StreamHandler()
handler.setFormatter(DecryptXFormatter())
decryptXLogger.handlers = [handler]