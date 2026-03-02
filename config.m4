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

  CFLAGS="$CFLAGS -DOPENSSL_API_3_0"
  CXXFLAGS="$CXXFLAGS -DOPENSSL_API_3_0"
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
