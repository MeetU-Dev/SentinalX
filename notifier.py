import logging
import subprocess

LOGGER = logging.getLogger(__name__)


def send_notification(title, message):
    # notify-send is the standard Linux user-space notification utility
    try:
        subprocess.run(['notify-send', title, message], check=True)
    except FileNotFoundError:
        LOGGER.warning('notify-send not installed; skipping system notification')
    except subprocess.CalledProcessError as exc:
        LOGGER.error('notify-send failed: %s', exc)
    except Exception as exc:
        LOGGER.exception('Unexpected error sending notification: %s', exc)
