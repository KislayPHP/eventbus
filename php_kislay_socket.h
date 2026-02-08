#ifndef PHP_KISLAYPHP_EVENTBUS_H
#define PHP_KISLAYPHP_EVENTBUS_H

extern "C" {
#include "php.h"
}

#define PHP_KISLAYPHP_EVENTBUS_VERSION "0.1"
#define PHP_KISLAYPHP_EVENTBUS_EXTNAME "kislayphp_eventbus"

extern zend_module_entry kislayphp_eventbus_module_entry;
#define phpext_kislayphp_eventbus_ptr &kislayphp_eventbus_module_entry

#endif
