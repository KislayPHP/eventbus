PHP_ARG_ENABLE(kislayphp_eventbus, whether to enable kislayphp_eventbus,
[  --enable-kislayphp_eventbus   Enable kislayphp_eventbus support])

if test "$PHP_KISLAYPHP_EVENTBUS" != "no"; then
  PHP_REQUIRE_CXX()

  CIVETWEB_INCLUDE_DIR=`pwd`/../https/third_party/civetweb/include
  PHP_ADD_INCLUDE($CIVETWEB_INCLUDE_DIR)

  PKG_CHECK_MODULES([OPENSSL], [openssl])
  PHP_EVAL_INCLINE($OPENSSL_CFLAGS)
  PHP_EVAL_LIBLINE($OPENSSL_LIBS, KISLAYPHP_EVENTBUS_SHARED_LIBADD)

  CFLAGS="$CFLAGS -DOPENSSL_API_3_0"
  CXXFLAGS="$CXXFLAGS -DOPENSSL_API_3_0"

  PHP_NEW_EXTENSION(kislayphp_eventbus, kislay_socket.cpp ../https/third_party/civetweb/src/civetweb.c, $ext_shared)
fi
