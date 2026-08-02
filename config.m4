PHP_ARG_ENABLE(kislayphp_eventbus, whether to enable kislayphp_eventbus,
[  --enable-kislayphp_eventbus   Enable kislayphp_eventbus support])

if test "$PHP_KISLAYPHP_EVENTBUS" != "no"; then
  PHP_REQUIRE_CXX()

  CIVETWEB_INCLUDE_DIR=`pwd`/third_party/civetweb/include
  PHP_ADD_INCLUDE($CIVETWEB_INCLUDE_DIR)

  PKG_CHECK_MODULES([OPENSSL], [openssl])
  PHP_EVAL_INCLINE($OPENSSL_CFLAGS)
  PHP_EVAL_LIBLINE($OPENSSL_LIBS, KISLAYPHP_EVENTBUS_SHARED_LIBADD)
  PHP_ADD_LIBRARY(stdc++,, KISLAYPHP_EVENTBUS_SHARED_LIBADD)
  PHP_SUBST(KISLAYPHP_EVENTBUS_SHARED_LIBADD)

  dnl USE_WEBSOCKET/NO_SSL_DL: see kislayphp/socket's config.m4 for the full
  dnl explanation (same vendored civetweb.c, same two bugs) - without
  dnl USE_WEBSOCKET every WS upgrade silently gets no response at all;
  dnl without NO_SSL_DL, civetweb's own OpenSSL dlopen/dlsym table is never
  dnl populated for a plain-HTTP server, and the SHA1 digest needed for the
  dnl handshake calls through a NULL function pointer, segfaulting on the
  dnl very first upgrade attempt.
  dnl -fvisibility=hidden + -DCIVETWEB_API=: see kislayphp/socket's config.m4
  dnl for the full explanation. civetweb.c exports ~200 non-static C
  dnl functions with default visibility (civetweb.h's CIVETWEB_API macro
  dnl re-asserts this regardless of -fvisibility unless pre-defined empty);
  dnl PHP extension bundles link -flat_namespace here, so 2+ co-loaded
  dnl extensions that each vendor civetweb.c can silently shadow each
  dnl other's compiled copy. get_module() stays exported via
  dnl ZEND_GET_MODULE's own ZEND_DLEXPORT regardless of this flag.
  CFLAGS="$CFLAGS -DOPENSSL_API_3_0 -DUSE_WEBSOCKET -DNO_SSL_DL -fvisibility=hidden -DCIVETWEB_API="
  CXXFLAGS="$CXXFLAGS -DOPENSSL_API_3_0 -DUSE_WEBSOCKET -DNO_SSL_DL -fvisibility=hidden -DCIVETWEB_API="
  if test -f ../rpc/gen/platform.pb.cc; then
    RPC_GEN_DIR=`pwd`/../rpc/gen
    PHP_ADD_INCLUDE($RPC_GEN_DIR)
    PHP_ADD_INCLUDE(`pwd`/../rpc)
    PKG_CHECK_MODULES([GRPC], [grpc++])
    PHP_EVAL_INCLINE($GRPC_CFLAGS)
    PHP_EVAL_LIBLINE($GRPC_LIBS, KISLAYPHP_EVENTBUS_SHARED_LIBADD)
    CXXFLAGS="$CXXFLAGS -DKISLAYPHP_RPC"
    RPC_SRCS="../rpc/gen/platform.pb.cc ../rpc/gen/platform.grpc.pb.cc"
  else
    AC_MSG_WARN([RPC stubs not found. Building without RPC support])
    RPC_SRCS=""
  fi

  PHP_NEW_EXTENSION(kislayphp_eventbus, kislay_socket.cpp third_party/civetweb/src/civetweb.c $RPC_SRCS, $ext_shared)
fi
