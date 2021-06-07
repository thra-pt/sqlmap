#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import ATHENA_SYSTEM_DBS
from lib.core.unescaper import unescaper

from plugins.dbms.athena.enumeration import Enumeration
from plugins.dbms.athena.filesystem import Filesystem
from plugins.dbms.athena.fingerprint import Fingerprint
from plugins.dbms.athena.syntax import Syntax
from plugins.dbms.athena.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class AthenaMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines Athena methods
    """

    def __init__(self):
        self.excludeDbsList = ATHENA_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.ATHENA] = Syntax.escape
