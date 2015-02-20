import logging
from logging import handlers

logger = logging.getLogger(__name__)
handler = handlers.SysLogHandler(address='/dev/log')
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    'tordyguards.%(module)s: %(levelname)s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


