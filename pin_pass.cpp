#include <iostream>
#include "pin.H"
#include <fstream>
#include <string>
#include <list>
#include <vector>
#include <unordered_map>
#include <exception>
#include <sstream>
#include <stack>

using std::string;
using std::cerr;
using std::endl;

// debug macros
#define DEBUG
// // instruction categories
#define INST_CAT
// exit on overflow
#define OVERFLOW
// ext-2 i.e. unknown instruction support
#define UNOWNED

// Argv[6] is the program image
std::string ProgramImage;

// output
std::ofstream OutFile;

// to string patch
namespace patch
{
    template < typename T > std::string to_string( const T& n )
    {
        std::ostringstream stm ;
        stm << n ;
        return stm.str() ;
    }
}

// implementing split function, which is analogous to the boost split function
template <typename Split>
void split(const string &s, char delim, Split result) {
    std::istringstream iss(s);
    string item;
    while (std::getline(iss, item, delim)) {
        *result++ = item;
    }
}

std::vector<string> split(const string &s, char delim) {
    std::vector<string> elems;
    split(s, delim, std::back_inserter(elems));
    return elems;
}

// count instrumentation category reached
#ifdef INST_CAT
static int64_t count_1 = 0;
static int64_t count_2 = 0;
static int64_t count_3 = 0;
static int64_t count_4 = 0;
static int64_t count_5 = 0;
static int64_t count_6 = 0;
static int64_t count_7 = 0;
#endif
// argv adress pointers
std::vector<int> argv_sizes;

// Object to store the malloc/ calloc/ realloc information per allocation
class MallocMap
{
  uint64_t size;
  uint64_t address;
  // todo: experimental
  bool check;
public:
  MallocMap(uint64_t address, uint64_t size, bool check){this->address = address; this->size = size; this->check=check;}
  void setmem(uint64_t address, uint64_t size, bool check){this->address = address; this->size = size; this->check=check;}
  void setsize(uint64_t size) {this->size = size;}
  void setcheck(uint64_t check) {this->check = check;}
  uint64_t getsize() {return this->size;}
  uint64_t getaddress() {return this->address;}
  bool getcheck() {return this->check;}
};

// To hold each allocation
std::map<uint64_t, MallocMap*> mallocmap;

// access bounds
class AccessBounds
{
private:
  // base and bounds of the object pointer to
  std::stack <uint64_t> base;
  std::stack <uint64_t> bound;
  // set location information
  // stacks store bounds information per object
  std::stack <uint64_t> mem_base;
  std::stack <uint64_t> mem_bound;
  // isempty
public:
  AccessBounds(uint64_t mem_base, uint64_t mem_bound)
  {this->mem_base.push(mem_base); this->mem_bound.push(mem_bound); this->base.push(0); this->bound.push(0);}
  void set_membounds(uint64_t mem_base, uint64_t mem_bound)
  {this->mem_base.push(mem_base); this->mem_bound.push(mem_bound); this->base.push(0); this->bound.push(0);}
  void set_bounds(uint64_t base, uint64_t bound)
  {this->base.pop(); this->bound.pop(); this->base.push(base); this->bound.push(bound);}
  uint64_t get_base(){return this->base.top();}
  uint64_t get_bound(){return this->bound.top();}
  uint64_t get_membase(){return this->mem_base.top();}
  uint64_t get_membound(){return this->mem_bound.top();}
  // this will remove top bounds and location information
  void remove_bounds(){this->mem_base.pop();this->mem_bound.pop();this->base.pop();this->bound.pop();}
  // check if all the stacks are empty
  // if an object is empty, then it can be removed in stack epilogue
  bool is_empty(){return (this->mem_base.empty()==true) && (this->mem_bound.empty()==true);}
};

// Map to store all bound information globally
// key: owner
std::unordered_map <std::string, AccessBounds*> accessboundsmap;

// contains the information of all the global objects (like data of bss section)
class GlobObjInfo
{
private:
  // Location from the base pointer and the upper bound
  int64_t ub;
  // Object Type
  std::string obj;
  // Object name
  std::string owner;
  // Object size
  int64_t obj_size;
  // lower bound
  int64_t lb;
public:
  GlobObjInfo(int64_t lb, std::string obj, string owner, int64_t obj_size)
  {
    this->lb = lb + obj_size;
    this->obj = obj;
    this->owner = owner;
    this->obj_size = obj_size;
    // Lower bounds calculated here
    this->ub = lb;
  }
  int64_t get_ub() {return ub;}
  std::string get_obj() {return obj;}
  std::string get_owner() {return owner;}
  int64_t get_obj_size() {return obj_size;}
  int64_t get_lb() {return lb;}
};

// A stack to store all the global variables
std::unordered_map <std::string, GlobObjInfo*> globalobjinfostack;

// Contains the information of all the objects
class ObjInfo
{
private:
  // Location from the base pointer and the upper bound
  int64_t ub;
  // Object Type
  std::string obj;
  // Object name
  std::string owner;
  // Object size
  int64_t obj_size;
  // lower bound
  int64_t lb;
public:
  ObjInfo(int64_t ub, std::string obj, string owner, int64_t obj_size)
  {
    this->ub = ub;
    this->obj = obj;
    this->owner = owner;
    this->obj_size = obj_size;
    // Lower bounds calculated here
    this->lb = ub + obj_size;
  }
  int64_t get_ub() {return ub;}
  std::string get_obj() {return obj;}
  std::string get_owner() {return owner;}
  int64_t get_obj_size() {return obj_size;}
  int64_t get_lb() {return lb;}
};

// Owner infomation of each location (address)
class InsInfo
{
private:
  ADDRINT address;
  std::string owner;
public:
  InsInfo(ADDRINT address, std::string owner) { this->address = address; this->owner = owner;}
  ADDRINT get_address() {return address;}
  std::string get_owner() {return owner;}
};

// A structure to store all the file related information
struct Block
{
  // Block name
  std::string name;
  // Set the rbp value for the particular block
  uint64_t rbp_value;
  // Set the rsp value for the particular block
  uint64_t rsp_value;
  // check if rbp relative addressing is used
  ADDRINT fun_entry;
  // function exit address
  ADDRINT fun_exit;
  // rsp/rbp
  uint64_t rsp_rbp;
  // argstack size
  uint64_t parameter;
  // stack size
  uint64_t stack_size;
  // Object information hash map
  std::unordered_map <std::string, ObjInfo*> objinfostack;
  // static code locations hash map
  std::unordered_map <ADDRINT, InsInfo*> inscodestack;
};

// Map containing Blocks
// The keys are function name and the values are blocks per function
std::unordered_map <std::string, struct Block*> blocks;

VOID set_stack(CONTEXT * ctxt, Block &i)
{
  #ifdef INST_CAT
  count_1++;
  #endif
  i.rsp_value = PIN_GetContextReg(ctxt, REG_RSP) - i.rsp_rbp;
  // i.rsp_value = PIN_GetContextReg(ctxt, REG_RSP) + 8;
  i.parameter = i.parameter+i.rsp_value;
  i.stack_size = i.rsp_value - i.stack_size;
  std::cout << "setting stack for: " << i.name << ", at " <<std::hex<< i.rsp_value << std::dec << '\n';
  for(std::unordered_map<std::string, ObjInfo*>::iterator iter = i.objinfostack.begin(); iter != i.objinfostack.end(); ++iter)
  {
    std::string k = iter->first;
    ObjInfo* v = iter->second;
    // set variables and their bounds in a global structure
    if(accessboundsmap.find(k) == accessboundsmap.end())
    {
      accessboundsmap.insert(std::make_pair(k, new AccessBounds(v->get_lb() +
        i.rsp_value, v->get_ub() + i.rsp_value)));
    }
    else
    {
      accessboundsmap[k]->set_membounds(v->get_lb() + i.rsp_value,
        v->get_ub() + i.rsp_value);
    }
  }

  // commandline arguments
  // only for function main
  if (i.name == "main")
  {
    uint64_t effective_dispacement = 0;
    effective_dispacement =  PIN_GetContextReg(ctxt, REG_RSI);
    accessboundsmap.insert(std::make_pair("main_cmdarg", new AccessBounds(effective_dispacement
    + PIN_GetContextReg(ctxt, REG_RDI) * 8, effective_dispacement)));

    // insert each commandline argument as an object
    for (ADDRINT j=0; j<PIN_GetContextReg(ctxt, REG_RDI);++j)
    {
      ADDRINT * addr_ptr = (ADDRINT*)effective_dispacement+j;
      ADDRINT value;
      PIN_SafeCopy(&value,addr_ptr, sizeof(ADDRINT));
      // if(accessboundsmap.find("main_argv_"+patch::to_string(j)) == accessboundsmap.end())
      accessboundsmap.insert(std::make_pair("main_argv_"+patch::to_string(j), new AccessBounds(
        value+argv_sizes[j]+1, value)));
    }
  }
}

VOID unset_stack(CONTEXT * ctxt, Block &i)
{
  #ifdef INST_CAT
  count_2++;
  #endif
  for(auto iter = accessboundsmap.begin(); iter != accessboundsmap.end();)
  {
    // find key with functionname_ substring and remove objects
    std::string k = iter->first;
    AccessBounds* v = iter->second;
    if (k.find(i.name+"_") != string::npos)
    {
      v->remove_bounds();
      if (v->is_empty())
      {
        #ifdef DEBUG
        std::cout << "cleared!" << '\n';
        #endif
        accessboundsmap.erase(iter++);
        continue;
      }
    }
    ++iter;
  }
}

////////////// store routines //////////////

// mov  DWORD PTR [rbp-ptr],address
VOID store_ptr_xfer_mem(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
std::string owner, int64_t displacement, int64_t scale, REG index_reg, REG base_reg,
int64_t ins_size, ADDRINT imm)
{
  #ifdef DEBUG
  std::cout << "ADD: " << std::hex << addr << ", Diss: " << disassins << std::dec << '\n';
  #endif
  #ifdef INST_CAT
  count_3++;
  #endif
  // support mov address instructions - this is not full proof as immediate may not be an address
  for(std::unordered_map<std::string, AccessBounds*>::iterator iter = accessboundsmap.begin(); iter != accessboundsmap.end(); ++iter)
  {
    std::string k = iter->first;
    AccessBounds* v = iter->second;
    if (imm == v->get_membound())
    {accessboundsmap[owner]->set_bounds(accessboundsmap[k]->get_membase(),
        accessboundsmap[k]->get_membound());
        #ifdef DEBUG
        std::cout << "bounds transfered from " << k << '\n';
        #endif
        return;}
  }
  if (mallocmap.find(imm) != mallocmap.end())
  {
    #ifdef DEBUG
    std::cout << "mallocmap find " << std::hex << imm << std::dec << '\n';
    #endif
    accessboundsmap[owner]->set_bounds(
      imm+mallocmap[imm]->getsize(),
      imm);
    return;
  }
  // check for in block accesses
  for (std::map<uint64_t, MallocMap*>::iterator iter = mallocmap.begin(); iter != mallocmap.end(); ++iter)
  {
    MallocMap* v = iter->second;
    if (imm < v->getaddress()+v->getsize() && imm >= v->getaddress())
    {
      #ifdef DEBUG
      std::cout << "mallocmap find " << std::hex << imm << std::dec << '\n';
      #endif
      accessboundsmap[owner]->set_bounds(
        v->getaddress()+v->getsize(),
        v->getaddress());
    }
  }
}

// mov  DWORD PTR [rbp-ptr],reg
VOID store_ptr_xfer_reg(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
std::string owner, int64_t displacement, int64_t scale, REG index_reg, REG base_reg,
int64_t ins_size, REG reg)
{
  #ifdef INST_CAT
  count_3++;
  #endif
  // now check if this instruction leads to pointer propagation
  if (REG_Width(reg)!=3)
  return;
  #ifdef DEBUG
  std::cout << "ADD: " << std::hex << addr << ", Diss: " << disassins << std::dec << '\n';
  // std::cout << std::hex << "reg: " << PIN_GetContextReg(ctxt, reg) << std::dec << '\n';
  #endif
  // todo: possible optimization just like immediate
  for(std::unordered_map<std::string, AccessBounds*>::iterator iter = accessboundsmap.begin(); iter != accessboundsmap.end(); ++iter)
  {
    std::string k = iter->first;
    AccessBounds* v = iter->second;
    if (PIN_GetContextReg(ctxt, reg) < v->get_membase() && PIN_GetContextReg(ctxt, reg) >= v->get_membound())
    {accessboundsmap[owner]->set_bounds(accessboundsmap[k]->get_membase(),
        accessboundsmap[k]->get_membound());
      #ifdef DEBUG
      std::cout << "bounds transfered from " << k << '\n';
      #endif
      return;}
  }
  // check if mem pointer
  if (mallocmap.find(PIN_GetContextReg(ctxt, reg)) != mallocmap.end())
  {
    #ifdef DEBUG
    std::cout << "mallocmap find " << std::hex << PIN_GetContextReg(ctxt, reg) << std::dec << '\n';
    #endif
    accessboundsmap[owner]->set_bounds(
      PIN_GetContextReg(ctxt, reg)+mallocmap[PIN_GetContextReg(ctxt, reg)]->getsize(),
      PIN_GetContextReg(ctxt, reg));
    return;
  }
  // check for in block accesses
  for (std::map<uint64_t, MallocMap*>::iterator iter = mallocmap.begin(); iter != mallocmap.end(); ++iter)
  {
    MallocMap* v = iter->second;
    if (PIN_GetContextReg(ctxt, reg) < v->getaddress()+v->getsize() && PIN_GetContextReg(ctxt, reg) >= v->getaddress())
    {
      #ifdef DEBUG
      std::cout << "mallocmap find " << std::hex << PIN_GetContextReg(ctxt, reg) << std::dec << '\n';
      #endif
      accessboundsmap[owner]->set_bounds(
        v->getaddress()+v->getsize(),
        v->getaddress());
    }
  }
}

// mov  DWORD PTR [*ptr],imm
// mov  DWORD PTR [rax],imm
VOID store_ptr_bnd_chk(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
std::string owner, int64_t displacement, int64_t scale, REG index_reg, REG base_reg,
int64_t ins_size)
{
  #ifdef DEBUG
  std::cout << "ADD: " << std::hex << addr << ", Diss: " << disassins << std::dec << '\n';
  #endif
  #ifdef INST_CAT
  count_4++;
  #endif
  uint64_t effective_dispacement = 0;
  // if the owner is on stack
  if (i.objinfostack.find(owner) != i.objinfostack.end())
  {
    if (REG_valid(index_reg))
    effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg)
      + (PIN_GetContextReg(ctxt, index_reg) * scale);
    else
    effective_dispacement = PIN_GetContextReg(ctxt, base_reg) + displacement;
  }
  // if owner is global
  else if (globalobjinfostack.find(owner) != globalobjinfostack.end())
  {
    if (REG_valid(index_reg))
    { // if index register is present, add it
      if (base_reg == REG_RIP)
      effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg)
      + (PIN_GetContextReg(ctxt, index_reg) * scale) + ins_size;
      else
      effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg)
      + (PIN_GetContextReg(ctxt, index_reg) * scale);
    }
    else
    {
      // if index register is not present
      if (base_reg == REG_RIP)
        effective_dispacement = PIN_GetContextReg(ctxt, base_reg) + displacement + ins_size;
      else
        effective_dispacement = PIN_GetContextReg(ctxt, base_reg) + displacement;
    }
  }
  #ifdef DEBUG
  std::cout << "effective_dispacement: " << std::hex << effective_dispacement << std::dec << '\n';
  std::cout << "Upper bounds: " << std::hex << accessboundsmap[owner]->get_membound() << std::dec << '\n';
  std::cout << "Lower bounds: " << std::hex << accessboundsmap[owner]->get_membase() << std::dec << '\n';
  std::cout << "ub: " << std::hex << accessboundsmap[owner]->get_bound() << std::dec << '\n';
  std::cout << "lb: " << std::hex << accessboundsmap[owner]->get_base() << std::dec << '\n';
  #endif
  // bound check
  if (accessboundsmap[owner]->get_base()==0)
    return;
  if ((effective_dispacement >= accessboundsmap[owner]->get_base() ||
  effective_dispacement < accessboundsmap[owner]->get_bound()))
  {
    std::cout << "Boundover accessed by " << owner << " in store_ptr_bnd_chk, at "
      << std::hex << addr << std::dec << '\n';
      // std::exit(1);
      #ifdef OVERFLOW
       PIN_ExitApplication(1);
      #endif
  }
}

// mov  DWORD PTR [rbp-arr],imm
VOID store_arr_bnd_chk(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
std::string owner, int64_t displacement, int64_t scale, REG index_reg, REG base_reg,
int64_t ins_size)
{
  #ifdef DEBUG
  std::cout << "ADD: " << std::hex << addr << ", Diss: " << disassins << std::dec << '\n';
  #endif
  #ifdef INST_CAT
  count_5++;
  #endif
  uint64_t effective_dispacement = 0;
  // if the owner is on stack
  if (i.objinfostack.find(owner) != i.objinfostack.end())
  {
    if (REG_valid(index_reg))
    effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg)
      + (PIN_GetContextReg(ctxt, index_reg) * scale);
    else
    effective_dispacement = PIN_GetContextReg(ctxt, base_reg) + displacement;
  }
  // if owner is global
  else if (globalobjinfostack.find(owner) != globalobjinfostack.end())
  {
    if (REG_valid(index_reg))
    { // if index register is present, add it
      if (base_reg == REG_RIP)
      effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg)
      + (PIN_GetContextReg(ctxt, index_reg) * scale) + ins_size;
      else
      effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg)
      + (PIN_GetContextReg(ctxt, index_reg) * scale);
    }
    else
    {
      // if index register is not present
      if (base_reg == REG_RIP)
        effective_dispacement = PIN_GetContextReg(ctxt, base_reg) + displacement + ins_size;
      else
        effective_dispacement = PIN_GetContextReg(ctxt, base_reg) + displacement;
    }
  }
  // if owner is nowhere to be found!
  else return;
  #ifdef DEBUG
  std::cout << "effective_dispacement: " << std::hex << effective_dispacement << std::dec << '\n';
  std::cout << "Upper bounds: " << std::hex << accessboundsmap[owner]->get_membound() << std::dec << '\n';
  std::cout << "Lower bounds: " << std::hex << accessboundsmap[owner]->get_membase() << std::dec << '\n';
  std::cout << "ub: " << std::hex << accessboundsmap[owner]->get_bound() << std::dec << '\n';
  std::cout << "lb: " << std::hex << accessboundsmap[owner]->get_base() << std::dec << '\n';
  #endif
  if ((effective_dispacement >= accessboundsmap[owner]->get_membase() ||
  effective_dispacement < accessboundsmap[owner]->get_membound()))
  {
    std::cout << "Boundover accessed by " << owner << " in store_arr_bnd_chk, at "
      << std::hex << addr << std::dec << '\n';
      #ifdef OVERFLOW
       PIN_ExitApplication(1);
      #endif
  }
}

////////////// load routines //////////////
// mov  eax,DWORD PTR [rbp-ptr]
VOID load_ptr_bnd_chk(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
std::string owner, int64_t displacement, int64_t scale, REG index_reg, REG base_reg, int64_t ins_size)
{
  #ifdef DEBUG
  std::cout << "ADD: " << std::hex << addr << ", Diss: " << disassins << std::dec << '\n';
  #endif
  #ifdef INST_CAT
  count_4++;
  #endif
  // initialize the effective displacement
  uint64_t effective_dispacement = 0;
  if (i.objinfostack.find(owner) != i.objinfostack.end())
  {
    if (REG_valid(index_reg))
      effective_dispacement = displacement + (PIN_GetContextReg(ctxt, base_reg))
      + (PIN_GetContextReg(ctxt, index_reg) * scale);
    else
      effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg);
  }
  else if (globalobjinfostack.find(owner) != globalobjinfostack.end())
  {
    if (REG_valid(index_reg))
    { // if index register is present, add it
      if (base_reg == REG_RIP)
      effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg)
      + (PIN_GetContextReg(ctxt, index_reg) * scale) + ins_size;
      else
      effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg)
      + (PIN_GetContextReg(ctxt, index_reg) * scale);
    }
    else
    {
      // if index register is not present
      if (base_reg == REG_RIP)
        effective_dispacement = PIN_GetContextReg(ctxt, base_reg) + displacement + ins_size;
      else
        effective_dispacement = PIN_GetContextReg(ctxt, base_reg) + displacement;
    }
  }
  #ifdef DEBUG
  std::cout << "effective_dispacement: " << std::hex << effective_dispacement << std::dec << '\n';
  std::cout << "Upper bounds: " << std::hex << accessboundsmap[owner]->get_membound() << std::dec << '\n';
  std::cout << "Lower bounds: " << std::hex << accessboundsmap[owner]->get_membase() << std::dec << '\n';
  std::cout << "Ub: " << std::hex << accessboundsmap[owner]->get_bound() << std::dec << '\n';
  std::cout << "Lb: " << std::hex << accessboundsmap[owner]->get_base() << std::dec << '\n';
  std::cout << "in mem_load" << '\n';
  #endif
  // bound check
  if (accessboundsmap[owner]->get_base()==0)
    return;
  if ((effective_dispacement >= accessboundsmap[owner]->get_base() ||
  effective_dispacement < accessboundsmap[owner]->get_bound()))
  {
    std::cout << "Boundover accessed by " << owner << " in load_ptr_bnd_chk, at "
      << std::hex << addr << std::dec << '\n';
      #ifdef OVERFLOW
       PIN_ExitApplication(1);
      #endif
  }
}

VOID load_arr_bnd_chk(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
std::string owner, int64_t displacement, int64_t scale, REG index_reg, REG base_reg, int64_t ins_size)
{
  #ifdef DEBUG
  std::cout << "ADD: " << std::hex << addr << ", Diss: " << disassins << std::dec << '\n';
  #endif
  #ifdef INST_CAT
  count_5++;
  #endif
  // initialize the effective displacement
  uint64_t effective_dispacement = 0;
  if (i.objinfostack.find(owner) != i.objinfostack.end())
  {
    if (REG_valid(index_reg))
      effective_dispacement = displacement + (PIN_GetContextReg(ctxt, base_reg))
      + (PIN_GetContextReg(ctxt, index_reg) * scale);
    else
      effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg);
  }
  else if (globalobjinfostack.find(owner) != globalobjinfostack.end())
  {
    if (REG_valid(index_reg))
    { // if index register is present, add it
      if (base_reg == REG_RIP)
      effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg)
      + (PIN_GetContextReg(ctxt, index_reg) * scale) + ins_size;
      else
      effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg)
      + (PIN_GetContextReg(ctxt, index_reg) * scale);
    }
    else
    {
      // if index register is not present
      if (base_reg == REG_RIP)
        effective_dispacement = PIN_GetContextReg(ctxt, base_reg) + displacement + ins_size;
      else
        effective_dispacement = PIN_GetContextReg(ctxt, base_reg) + displacement;
    }
  }
  #ifdef DEBUG
  std::cout << "effective_dispacement: " << std::hex << effective_dispacement << std::dec << '\n';
  std::cout << "Upper bounds: " << std::hex << accessboundsmap[owner]->get_membound() << std::dec << '\n';
  std::cout << "Lower bounds: " << std::hex << accessboundsmap[owner]->get_membase() << std::dec << '\n';
  std::cout << "Ub: " << std::hex << accessboundsmap[owner]->get_bound() << std::dec << '\n';
  std::cout << "Lb: " << std::hex << accessboundsmap[owner]->get_base() << std::dec << '\n';
  std::cout << "in mem_load" << '\n';
  #endif
  if (effective_dispacement >= accessboundsmap[owner]->get_membase() ||
  effective_dispacement < accessboundsmap[owner]->get_membound())
  {
    std::cout << "Boundover access detected. By " << owner << " in load_arr_bnd_chk, at "
    << std::hex << addr << std::dec << '\n';
    #ifdef OVERFLOW
     PIN_ExitApplication(1);
    #endif
  }
}

VOID unknown_loadstore(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
std::string owner, int64_t displacement, int64_t scale, REG index_reg, REG base_reg, int64_t ins_size)
{
  #ifdef DEBUG
  std::cout << "ADD: " << std::hex << addr << ", Diss: " << disassins << std::dec << '\n';
  std::cout << "disp: " << displacement << '\n';
  #endif
  #ifdef INST_CAT
  count_7++;
  #endif
  // initialize the effective displacement
  uint64_t effective_dispacement = 0;
  if (REG_valid(index_reg))
    effective_dispacement = displacement + (PIN_GetContextReg(ctxt, base_reg))
    + (PIN_GetContextReg(ctxt, index_reg) * scale);
  else
    effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg);
  std::cout << "effective_dispacement: " << std::hex << effective_dispacement << std::dec << '\n';
  // std::cout << "i.stack_size: " << i.stack_size << '\n';
  // std::cout << "i.parameter: " << i.parameter << '\n';
  if ((effective_dispacement > i.parameter) || (effective_dispacement < i.rsp_value+8 && effective_dispacement >= i.rsp_value) || (effective_dispacement < i.stack_size))
  {
    std::cout << "Boundover access detected. By " << owner << " in unknown_check, at "
    << std::hex << addr << std::dec << '\n';
    #ifdef OVERFLOW
     PIN_ExitApplication(1);
    #endif
  }
}

// instruction instrumentation
VOID Instruction(INS ins, VOID *v)
{
  // instruction address
  ADDRINT insaddress = INS_Address(ins);
  // skip if the address is over 0x700000000000
  if (insaddress > 0x700000000000)
    return;
  // First check if the routine is valid
  if (!RTN_Valid(RTN_FindByAddress(insaddress)))
    return;
  // collect function block if valid
  if ( blocks.find(RTN_Name(RTN_FindByAddress(insaddress))) == blocks.end())
    return;
  struct Block *i = blocks[RTN_Name(RTN_FindByAddress(insaddress))];
  // check if address is within the boundary
  if ((insaddress < i->fun_entry) || (insaddress > i->fun_exit))
    return;
  // if first instruction, then set the stack
  if (insaddress == i->fun_entry)
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)set_stack, IARG_CONTEXT, IARG_PTR, &(*i), IARG_END);

  if ((insaddress == i->fun_exit) or INS_IsRet(ins))
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)unset_stack, IARG_CONTEXT, IARG_PTR, &(*i), IARG_END);
  // print instruction with address
  // std::cout << string(INS_Disassemble(ins)) << " :" << std::hex << insaddress << std::dec << '\n';

  // collect owner
  std::string owner;
  if (i->inscodestack.find(insaddress) == i->inscodestack.end())
    return;
  else
    owner = i->inscodestack[insaddress]->get_owner();

  if (owner == "unknown")
  #ifdef UNOWNED
  {
    // instrument store instructions
    if (INS_OperandIsMemory(ins, 0))
    {
      if (REG_StringShort(INS_OperandMemoryBaseReg(ins, 0)) == "rbp" or REG_StringShort(INS_OperandMemoryBaseReg(ins, 0))== "rsp")
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)unknown_loadstore, IARG_ADDRINT,
      insaddress, IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
      IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 0),
      IARG_ADDRINT, INS_OperandMemoryScale(ins, 0), IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 0)),
      IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 0)),
      IARG_UINT32, INS_Size(ins), IARG_END);
    }
    else if (INS_OperandIsMemory(ins, 1))
    {
      if (REG_StringShort(INS_OperandMemoryBaseReg(ins, 1)) == "rbp" or REG_StringShort(INS_OperandMemoryBaseReg(ins, 1))== "rsp")
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)unknown_loadstore, IARG_ADDRINT,
      insaddress, IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
      IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 1),
      IARG_ADDRINT, INS_OperandMemoryScale(ins, 1), IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 1)),
      IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 1)),
      IARG_UINT32, INS_Size(ins), IARG_END);
    }
  }
  #else
  {return;}
  #endif

  std::string obj;
  // int64_t obj_size;
  if (i->objinfostack.find(owner) != i->objinfostack.end())
  {
    obj = i->objinfostack[owner]->get_obj();
    // obj_size = i->objinfostack[owner]->get_obj_size();
  }
  else if(globalobjinfostack.find(owner) != globalobjinfostack.end())
  {
    obj = globalobjinfostack[owner]->get_obj();
    // obj_size = globalobjinfostack[owner]->get_obj_size();
  }
  else return;
  // don't instrument if scalar (todo: this can be removed later)
  if (obj == "scalar")
    return;

  // instrument store instructions
  if (INS_OperandIsMemory(ins, 0))
  {
      // if pointer
      if (obj == "PTR")
      {
        // this pattern make sure that it is not a pointer dereference
        REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
        if (REG_StringShort(base_reg) == "rbp" or REG_StringShort(base_reg)== "rsp" or REG_StringShort(base_reg)== "rip")
        {
          if (INS_OperandIsImmediate(ins, 1))
          {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)store_ptr_xfer_mem, IARG_ADDRINT,
            insaddress, IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
            IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 0),
            IARG_ADDRINT, INS_OperandMemoryScale(ins, 0), IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 0)),
            IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 0)),
            IARG_UINT32, INS_Size(ins), IARG_ADDRINT, INS_OperandImmediate(ins, 1), IARG_END);
          }
          else if (INS_OperandIsReg(ins, 1))
          {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)store_ptr_xfer_reg, IARG_ADDRINT,
            insaddress, IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
            IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 0),
            IARG_ADDRINT, INS_OperandMemoryScale(ins, 0), IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 0)),
            IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 0)),
            IARG_UINT32, INS_Size(ins), IARG_UINT32, REG(INS_OperandReg(ins, 1)), IARG_END);
          }
        }
        else
        {
          INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)store_ptr_bnd_chk, IARG_ADDRINT,
          insaddress, IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
          IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 0),
          IARG_ADDRINT, INS_OperandMemoryScale(ins, 0), IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 0)),
          IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 0)),
          IARG_UINT32, INS_Size(ins), IARG_END);
        }
      }
    else
    {
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)store_arr_bnd_chk, IARG_ADDRINT,
      insaddress, IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
      IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 0),
      IARG_ADDRINT, INS_OperandMemoryScale(ins, 0), IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 0)),
      IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 0)),
      IARG_UINT32, INS_Size(ins), IARG_END);
    }
  }
  // instrument load instructions
  else if (INS_OperandIsMemory(ins, 1))
  {
    // if pointer
    if (obj == "PTR")
    {
      REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
      if (!(REG_StringShort(base_reg) == "rbp" or REG_StringShort(base_reg)== "rsp" or REG_StringShort(base_reg)== "rip"))
      {
          INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)load_ptr_bnd_chk, IARG_ADDRINT,
        insaddress, IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 1),
        IARG_ADDRINT, INS_OperandMemoryScale(ins, 1), IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 1)),
        IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 1)),
        IARG_UINT32, INS_Size(ins),
        IARG_END);
      }
    }
    else
    {
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)load_arr_bnd_chk, IARG_ADDRINT,
      insaddress, IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
      IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 1),
      IARG_ADDRINT, INS_OperandMemoryScale(ins, 1), IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 1)),
      IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 1)),
      IARG_UINT32, INS_Size(ins),
      IARG_END);
    }
  }
}

// Lazy size allocation
ADDRINT lazyallocatedsize = 0;

VOID malloc_before(char *name, ADDRINT count, ADDRINT size)
{
  #ifdef INST_CAT
  count_6++;
  #endif
  // if (name == "malloc" or name == "realloc")
  //   lazyallocatedsize = size;
  // else if (name == "calloc")
  lazyallocatedsize = count * size;
}

VOID malloc_after(ADDRINT addrs)
{
  #ifdef INST_CAT
  count_6++;
  #endif
  if (addrs == '\0')
  {
    cerr << "Heap full!\n";
    return;
  }
  if (mallocmap.find(addrs) == mallocmap.end())
  {
    #ifdef DEBUG
    std::cout << "size set: " << lazyallocatedsize << " at address: " << std::hex << addrs << std::dec << '\n';
    #endif
    mallocmap.insert(std::make_pair(addrs, new MallocMap(addrs, lazyallocatedsize, true)));
  }
  else
  {
    #ifdef DEBUG
    std::cout << "new size set: " << lazyallocatedsize << " at address: " << std::hex << addrs << std::dec << '\n';
    #endif
    mallocmap[addrs]->setmem(addrs, lazyallocatedsize, true);
  }
  lazyallocatedsize = 0;
}

VOID free_before(ADDRINT ret)
{
  #ifdef INST_CAT
  count_6++;
  #endif
  std::cout << "returns: " <<  ret << '\n';
}

// image instrumentation
void Image(IMG img, VOID *v)
{
  // instrument main image only
  if (IMG_IsMainExecutable(img))
  {
    // create routines per each user level function
    for(std::unordered_map<std::string, struct Block*>::iterator iter = blocks.begin(); iter != blocks.end(); ++iter)
    {
      std::string k = iter->first;
      struct Block* v = iter->second;
      RTN_CreateAt(v->fun_entry, v->name);
    }
  }
  // set library path accordingly
  // if (IMG_Name(img) == "/lib/x86_64-linux-gnu/libc.so.6")
  if (IMG_Name(img).find("libc") != std::string::npos)
  {
    RTN mallocRtn = RTN_FindByName(img, "malloc");
    if (RTN_Valid(mallocRtn))
    {
      RTN_Open(mallocRtn);
      // Instrument malloc() to print the input argument value and the return value.
      RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)malloc_before,
                    IARG_ADDRINT, "malloc",
                    IARG_ADDRINT, 1,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_END);
      RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)malloc_after,
                    IARG_FUNCRET_EXITPOINT_VALUE,
                    IARG_END);
      RTN_Close(mallocRtn);
    }
    RTN callocRtn = RTN_FindByName(img, "calloc");
    if (RTN_Valid(callocRtn))
    {
      RTN_Open(callocRtn);
      // Instrument malloc() to print the input argument value and the return value.
      RTN_InsertCall(callocRtn, IPOINT_BEFORE, (AFUNPTR)malloc_before,
                    IARG_ADDRINT, "calloc",
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_END);
      RTN_InsertCall(callocRtn, IPOINT_AFTER, (AFUNPTR)malloc_after,
                    IARG_FUNCRET_EXITPOINT_VALUE,
                    IARG_END);
      RTN_Close(callocRtn);
    }
    RTN reallocRtn = RTN_FindByName(img, "realloc");
    if (RTN_Valid(reallocRtn))
    {
      RTN_Open(reallocRtn);
      // Instrument malloc() to print the input argument value and the return value.
      RTN_InsertCall(reallocRtn, IPOINT_BEFORE, (AFUNPTR)malloc_before,
                    IARG_ADDRINT, "realloc",
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_END);
      RTN_InsertCall(reallocRtn, IPOINT_AFTER, (AFUNPTR)malloc_after,
                    IARG_FUNCRET_EXITPOINT_VALUE,
                    IARG_END);
      RTN_Close(reallocRtn);
    }
    RTN freeRtn = RTN_FindByName(img, "free");
    if (RTN_Valid(freeRtn))
    {
      RTN_Open(freeRtn);
      // Instrument malloc() to print the input argument value and the return value.
      RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)free_before,
                     IARG_FUNCRET_EXITPOINT_VALUE,
                     IARG_END);
      RTN_Close(freeRtn);
    }
  }
}

// read the input text file
void readInput(const char *filename)
{
  std::string line;
  std::ifstream myfile(filename);
  if (myfile.is_open())
  {
    // Get total number of functions or blocks
    getline (myfile,line);
    int64_t count = atoi(line.c_str());
    while (count)
    {
      // Initialize the structure
      struct Block *block = new Block;
      // for the function name
      getline (myfile,line);
      block->name = line;
      // todo: experimental
      block->rbp_value = 0;
      block->rsp_value = 0;
      // experimental line - to denote addressing mode
      // getline (myfile,line);
      getline(myfile,line);
      // get the function boundary information
      block->fun_entry = strtol(line.c_str(), NULL, 16);
      getline(myfile,line);
      block->fun_exit = strtol(line.c_str(), NULL, 16);
      // rsp/rbp
      getline(myfile,line);
      block->rsp_rbp = strtol(line.c_str(), NULL, 16);
      // argstack size
      getline(myfile,line);
      block->parameter = strtol(line.c_str(), NULL, 16);
      // stack size
      getline(myfile,line);
      block->stack_size = strtol(line.c_str(), NULL, 16);
      // RTN_CreateAt(block->fun_entry, block->name);
      // detect addresses
      getline (myfile,line);
      if (line == "addresses")
      {
        while (getline(myfile,line))
        {
          if (line.empty())
          {break;}
          else
          {
            std::vector<std::string> temp;
            // boost::split(temp, line, boost::is_any_of("\t "));
            temp = split(line, ' ');
            block->inscodestack.insert(std::make_pair(strtol(temp[0].c_str(), NULL, 16), new InsInfo(strtol(temp[0].c_str(), NULL, 16), temp[1])));
          }
        }
      }
      getline (myfile,line);
      if (line == "locals")
      {
        while (getline(myfile,line))
        {
          if (line.empty())
          {break;}
          else
          {
            std::vector<std::string> temp;
            //boost::split(temp, line, boost::is_any_of("\t "));
            temp = split(line, ' ');
            block->objinfostack.insert(std::make_pair(temp[2], new ObjInfo(atoi(temp[0].c_str()), temp[1], temp[2], atoi(temp[3].c_str()))));
          }
        }
      }
      if (!block->inscodestack.empty() || !block->objinfostack.empty())
        blocks.insert(std::make_pair(block->name, block));
      --count;
    }
    //global variables must be handled here
    getline (myfile,line);
    if (line == ".global")
    {
      while (getline(myfile,line))
      {
        if (line.empty())
        {break;}
        else
        {
          std::vector<std::string> temp;
          //boost::split(temp, line, boost::is_any_of("\t "));
          temp = split(line, ' ');
          globalobjinfostack.insert(std::make_pair(temp[2], new GlobObjInfo(atoi(temp[0].c_str()), temp[1], temp[2], atoi(temp[3].c_str()))));
        }
      }
    }
    myfile.close();
    // Assign respective owners per global or static location
    for(std::unordered_map<std::string, GlobObjInfo*>::iterator iter = globalobjinfostack.begin(); iter != globalobjinfostack.end(); ++iter)
    {
      std::string k = iter->first;
      GlobObjInfo* v = iter->second;
      if(accessboundsmap.find(k) == accessboundsmap.end())
        accessboundsmap.insert(std::make_pair(k, new AccessBounds(v->get_lb(), v->get_ub())));
    }
  }
  else std::cout << "Unable to open file\n";
}

// read text file through knob
KNOB<string> KnobInputFile(KNOB_MODE_WRITEONCE, "pintool",
    "i", "pintool", "specify input file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
  // Write to a file since cout and cerr maybe closed by the application
  OutFile << "CAT1: " << count_1 << endl;
  OutFile << "CAT2: " << count_2 << endl;
  OutFile << "CAT3: " << count_3 << endl;
  OutFile << "CAT4: " << count_4 << endl;
  OutFile << "CAT5: " << count_5 << endl;
  OutFile << "CAT6: " << count_6 << endl;
  OutFile << "CAT7: " << count_7 << endl;
  OutFile.close();
  std::cout << "Application exit" << '\n';
}

INT32 Usage()
{
    cerr << "use it with bin and txt" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

int main(int argc, char * argv[])
{
    // Symbols
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return Usage();
    // Argv[7] is the program image
    ProgramImage = argv[8];
    for (int i=8; i<argc; ++i)
    {
      // std::cout << "arg :" << i << " : " << strlen(argv[i]) << '\n';
      argv_sizes.push_back(strlen(argv[i]));
    }
    readInput(KnobInputFile.Value().c_str());
    // std::cout << "Total args: " << argc << '\n';
    // output
    std::string dir = ProgramImage.substr(0, ProgramImage.find_last_of("/\\"))+"/"+"catcount3.out";
    // todo: safe?
    OutFile.open(dir.c_str());
    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Image instrumentation
    IMG_AddInstrumentFunction(Image, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
