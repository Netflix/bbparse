LIB=		bbparse
SRCS=		${LIB}.c
LIBADD=		lzma
WARNS?=		6
DEBUG_FLAGS=	-g
MAN=		libbbparse.3

.include <bsd.lib.mk>
