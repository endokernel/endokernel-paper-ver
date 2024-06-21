#include <pkru.h>
#include <asm-offsets.h>
#define _CONCAT2(x,y) x##y
#define CONCAT2(x,y) _CONCAT2(x,y)
#define _CONCAT3(x,y,z) x##y##z
#define CONCAT3(x,y,z) _CONCAT3(x,y,z)

// TODO: As we are now using dynamic app_pkru from TLS
// We should merge the two trampolines
    
#define domain_begin(id) CONCAT2(app_safe_xcall_, id)
#define domain_table(id) CONCAT3(app_safe_xcall_, id, _table)
#define domain_end(id) CONCAT3(app_safe_xcall_, id, _end)
#define domain_cmp(id) CONCAT3(app_safe_xcall_, id, _cmp)
#define app_pkru safebox_pkru
.data
#undef domain_id
#define domain_id 3
#include "app_template.S"
#undef domain_id
#define domain_id 4
#include "app_template.S"
#undef domain_id
#define domain_id 5
#include "app_template.S"
#undef domain_id
#define domain_id 6
#include "app_template.S"
#undef domain_id
#define domain_id 7
#include "app_template.S"
#undef domain_id
#define domain_id 8
#include "app_template.S"
#undef domain_id
#define domain_id 9
#include "app_template.S"
#undef domain_id
#define domain_id 10
#include "app_template.S"
#undef domain_id
#define domain_id 11
#include "app_template.S"
#undef domain_id
#define domain_id 12
#include "app_template.S"
#undef domain_id
#define domain_id 13
#include "app_template.S"
#undef domain_id
#define domain_id 14
#include "app_template.S"
#undef domain_id
#define domain_id 15
#include "app_template.S"


#undef domain_begin
#undef domain_table
#undef domain_end
#undef domain_cmp
#undef app_pkru


#define domain_begin(id) CONCAT2(app2_safe_xcall_, id)
#define domain_table(id) CONCAT3(app2_safe_xcall_, id, _table)
#define domain_end(id) CONCAT3(app2_safe_xcall_, id, _end)
#define domain_cmp(id) CONCAT3(app2_safe_xcall_, id, _cmp)
#define app_pkru safebox_pkru
.data
#undef domain_id
#define domain_id 3
#include "app_template.S"
#undef domain_id
#define domain_id 4
#include "app_template.S"
#undef domain_id
#define domain_id 5
#include "app_template.S"
#undef domain_id
#define domain_id 6
#include "app_template.S"
#undef domain_id
#define domain_id 7
#include "app_template.S"
#undef domain_id
#define domain_id 8
#include "app_template.S"
#undef domain_id
#define domain_id 9
#include "app_template.S"
#undef domain_id
#define domain_id 10
#include "app_template.S"
#undef domain_id
#define domain_id 11
#include "app_template.S"
#undef domain_id
#define domain_id 12
#include "app_template.S"
#undef domain_id
#define domain_id 13
#include "app_template.S"
#undef domain_id
#define domain_id 14
#include "app_template.S"
#undef domain_id
#define domain_id 15
#include "app_template.S"


#undef domain_begin
#undef domain_table
#undef domain_end
#undef domain_cmp
#undef app_pkru
#define domain_begin(id) CONCAT2(app_sand_xcall_, id)
#define domain_table(id) CONCAT3(app_sand_xcall_, id, _table)
#define domain_end(id) CONCAT3(app_sand_xcall_, id, _end)
#define domain_cmp(id) CONCAT3(app_sand_xcall_, id, _cmp)
#define app_pkru sandbox_pkru
#define sandbox
.data
#undef domain_id
#define domain_id 3
#include "app_template.S"
#undef domain_id
#define domain_id 4
#include "app_template.S"
#undef domain_id
#define domain_id 5
#include "app_template.S"
#undef domain_id
#define domain_id 6
#include "app_template.S"
#undef domain_id
#define domain_id 7
#include "app_template.S"
#undef domain_id
#define domain_id 8
#include "app_template.S"
#undef domain_id
#define domain_id 9
#include "app_template.S"
#undef domain_id
#define domain_id 10
#include "app_template.S"
#undef domain_id
#define domain_id 11
#include "app_template.S"
#undef domain_id
#define domain_id 12
#include "app_template.S"
#undef domain_id
#define domain_id 13
#include "app_template.S"
#undef domain_id
#define domain_id 14
#include "app_template.S"
#undef domain_id
#define domain_id 15
#include "app_template.S"
#undef sandbox