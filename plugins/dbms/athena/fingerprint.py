#!/usr/bin/env python

"""
Copyright (c) 2021 Bishop Fox (www.bishopfox.com)
"""

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import ATHENA_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.ATHENA)

    def getFingerprint(self):
        value = ""
        wsOsFp = Format.getOs("web server", kb.headersFp)

        if wsOsFp:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = Format.getOs("back-end DBMS", kb.bannerFp)

            if dbmsOsFp:
                value += "%s\n" % dbmsOsFp

        value += "back-end DBMS: "

        if not conf.extensiveFp:
            value += DBMS.ATHENA
            return value

        actVer = Format.getDbms()
        blank = " " * 15
        value += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp.get("dbmsVersion")

            if banVer:
                banVer = Format.getDbms([banVer])
                value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        if not conf.extensiveFp and Backend.isDbmsWithin(ATHENA_ALIASES):
            setDbms(DBMS.ATHENA)

            self.getBanner()

            return True

        infoMsg = "testing %s" % DBMS.ATHENA
        logger.info(infoMsg)

        result = (inject.checkBooleanExpression("TO_BASE64URL(NULL) IS NULL")) and not (inject.checkBooleanExpression("POSITION(NULL) IS NULL"))

        if result:
            infoMsg = "confirming %s" % DBMS.ATHENA
            logger.info(infoMsg)

            result = (inject.checkBooleanExpression("TO_HEX(FROM_HEX(NULL)) IS NULL")) and not (inject.checkBooleanExpression("ENTROPY(NULL) IS NULL"))

            if not result:
                warnMsg = "the back-end DBMS is not %s" % DBMS.ATHENA
                logger.warn(warnMsg)

                return False

            setDbms(DBMS.ATHENA)

            return True
        else:
            warnMsg = "the back-end DBMS is not %s" % DBMS.ATHENA
            logger.warn(warnMsg)

            return False
