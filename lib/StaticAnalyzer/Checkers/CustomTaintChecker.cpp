//== CustomTaintChecker.cpp ----------------------------------- -*- C++ -*--=//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This checker defines the attack surface for generic taint propagation.
//
// The taint information produced by it might be useful to other checkers. For
// example, checkers should report errors which involve tainted data more
// aggressively, even if the involved symbols are under constrained.
//
// This checker is based on GenericTaintChecker, but it adds custom configuration
// for the checker retrieved from a xml resource.
//
//===----------------------------------------------------------------------===//

#include "includes/TaintParser.h"
#include "includes/TaintVisitor.h"

#include "clang/AST/Attr.h"
#include "ClangSACheckers.h"
#include "clang/Config/config.h"
#include "clang/Basic/Builtins.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/TaintTag.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"

#include "llvm/ADT/MapVector.h"
#include "llvm/Support/raw_ostream.h"

#include <climits>
#include <utility>

#ifdef CLANG_HAVE_LIBXML
#include <libxml/xpath.h>
#include <libxml/parser.h>
#include <libxml/xmlschemastypes.h>
#endif

using namespace clang;
using namespace ento;
using namespace std;
using namespace taintutil;
namespace {

// File used to write debug information(its path is passed by parameter to the
// checker).
static FILE* DebugFile;

// Location of configuration schema used to validate the configuration file
// entered by the user.
static const string ConfigSchema = string
  (CLANG_RESOURCE_DIR+(string)"/taint-rules.xsd");

class CustomTaintChecker : public Checker< check::PostStmt<CallExpr>,
                                            check::PreStmt<CallExpr> > {
public:
  CustomTaintChecker() {
    SourceMap = SOURCE();
    PropagationRuleMap = PROPAGATION();
    DestinationMap = DESTINATION();
    FilterMap = FILTER();
  }

  ~CustomTaintChecker() {
    fclose(DebugFile);
  }

  void initialization(string ConfigurationFilePath, string DebugFilePath) {
    
    // Displaying welcome screen.
    llvm::outs().changeColor(llvm::outs().SAVEDCOLOR, true, false);
    llvm::outs() << "############################" << "\n";
    llvm::outs() << "### Custom Taint Checker ###" << "\n";
    llvm::outs() << "############################" << "\n";
    
    llvm::outs() << "Configuration file: " << ConfigurationFilePath.data();
    llvm::outs() << "\n";
    llvm::outs() << "Debug file: " << DebugFilePath.data() << "\n";
    llvm::outs() << "\n";
    llvm::outs().changeColor(llvm::outs().SAVEDCOLOR, false, false);

    DebugFile = fopen(DebugFilePath.data(), "a");
    debug("\n------Starting checker------\n");

    // Instance Parser class.
    #if defined CLANG_HAVE_LIBXML
    TaintParser parser = TaintParser(ConfigurationFilePath, ConfigSchema);
    
    int result;
    if ((result = parser.process())==0){
      // Getting taint configuration data from TaintParser object.
      SourceMap = parser.getSourceMap();
      
      TaintParser::PROPAGATION propagationRule = parser.getPropagationRuleMap();
      for (TaintParser::PROPAGATION::const_iterator
           I = propagationRule.begin(),
           E = propagationRule.end(); I != E; ++I) {
        std::pair<std::string, TaintParser::PropagationRule> pair = *I;
        
        TaintPropagationRule taintPropagationRule = TaintPropagationRule();
        taintPropagationRule.setSrcArg(pair.second.SrcArgs);
        taintPropagationRule.setDstArg(pair.second.DstArgs);
        PropagationRuleMap.push_back(NAMEPROPAGATIONPAIR(pair.first,
                                                         taintPropagationRule));
      }
      
      DestinationMap = parser.getDestinationMap();
      FilterMap = parser.getFilterMap();
      debug(parser.toString().data());
    }
    else {
      // An error occurred trying to parse configuration file.
      switch (result){
        case parser.Errors::ValidationError:
          llvm::outs() <<
            "Configuration file does not validate against schema.\n";
          break;
        default:
          llvm::outs() <<
            "An error occurred trying to load configuration file.\n";
          break;
      }
      llvm::outs() <<
        "Loading just default configuration.\n\n";
    }
    #else
      debug("No LIBXML library found. Using default setting. \n");
    #endif
  }

  static void *getTag() { static int Tag; return &Tag; }

  void checkPostStmt(const CallExpr *CE, CheckerContext &C) const;

  void checkPreStmt(const CallExpr *CE, CheckerContext &C) const;

private:
  static const unsigned InvalidArgIndex = 101;
  /// Denotes the return vale.
  static const unsigned ReturnValueIndex = 100;

  mutable std::unique_ptr<BugType> BT;
  inline void initBugType() const {
    if (!BT)
      BT.reset(new BugType(this, "Use of Untrusted Data", "Untrusted Data"));
  }

  /// \brief Catch taint related bugs. Check if tainted data is passed to a
  /// system call etc.
  bool checkPre(const CallExpr *CE, CheckerContext &C) const;

  /// \brief Check if the method is a generator. If so, it is marked as a
  /// variable to be tainted on post-visit.
  void checkGenerators(const CallExpr *CE, CheckerContext &C) const;
  
  /// \brief Check if the method is a filter. If so, it is marked as a variable
  /// to be untainted on post-visit.
  void checkFilters(const CallExpr *CE, CheckerContext &C) const;
                                                
  /// \brief Add taint sources on a pre-visit.
  void addSourcesPre(const CallExpr *CE, CheckerContext &C) const;
                                                
  /// \brief Propagate taint generated at pre-visit.
  bool propagateFromPre(const CallExpr *CE, CheckerContext &C) const;

  /// \brief If the method was marked as filter at pre-visit, untaint
  /// the arguments specified by it.
  bool propagateFilterFromPre(const CallExpr *CE, CheckerContext &C) const;
                                                
  /// \brief Add taint sources on a post visit.
  void addSourcesPost(const CallExpr *CE, CheckerContext &C) const;

  bool isFDApplicable(const FunctionDecl* FD) const;

  /// Check if the region the expression evaluates to is the standard input,
  /// and thus, is tainted.
  static bool isStdin(const Expr *E, CheckerContext &C);

  /// \brief Given a pointer argument, get the symbol of the value it contains
  /// (points to).
  static SymbolRef getPointedToSymbol(CheckerContext &C, const Expr *Arg);

  /// Functions defining the attack surface.
  typedef ProgramStateRef (CustomTaintChecker::*FnCheck)(const CallExpr *,
                                                       CheckerContext &C) const;
  ProgramStateRef postScanf(const CallExpr *CE, CheckerContext &C) const;
  ProgramStateRef postSocket(const CallExpr *CE, CheckerContext &C) const;
  ProgramStateRef postRetTaint(const CallExpr *CE, CheckerContext &C) const;

  /// Taint the scanned input if the file is tainted.
  ProgramStateRef preFscanf(const CallExpr *CE, CheckerContext &C) const;

  /// Check for CWE-134: Uncontrolled Format String.
  static const char MsgUncontrolledFormatString[];
  bool checkUncontrolledFormatString(const CallExpr *CE,
                                     CheckerContext &C) const;
  static const char MsgSanitizeArgs[];
  bool checkCustomDestination(const CallExpr *CE, StringRef Name,
                       CheckerContext &C) const;

  /// Check for:
  /// CERT/STR02-C. "Sanitize data passed to complex subsystems"
  /// CWE-78, "Failure to Sanitize Data into an OS Command"
  static const char MsgSanitizeSystemArgs[];
  bool checkSystemCall(const CallExpr *CE, StringRef Name,
                       CheckerContext &C) const;

  /// Check if tainted data is used as a buffer size ins strn.. functions,
  /// and allocators.
  static const char MsgTaintedBufferSize[];
  bool checkTaintedBufferSize(const CallExpr *CE, const FunctionDecl *FDecl,
                              CheckerContext &C) const;

  /// Generate a report if the expression is tainted or points to tainted data.
  bool generateReportIfTainted(const Expr *E, const char Msg[],
                               CheckerContext &C) const;
                               
  
  typedef SmallVector<unsigned, 2> ArgVector;
 
  /// \brief A struct used to specify taint propagation rules for a function.
  ///
  /// If any of the possible taint source arguments is tainted, all of the
  /// destination arguments should also be tainted. Use InvalidArgIndex in the
  /// src list to specify that all of the arguments can introduce taint. Use
  /// InvalidArgIndex in the dst arguments to signify that all the non-const
  /// pointer and reference arguments might be tainted on return. If
  /// ReturnValueIndex is added to the dst list, the return value will be
  /// tainted.
  struct TaintPropagationRule {
    /// List of arguments which can be taint sources and should be checked.
    ArgVector SrcArgs;
    /// List of arguments which should be tainted on function return.
    ArgVector DstArgs;
    // TODO: Check if using other data structures would be more optimal.

    TaintPropagationRule() {}

    TaintPropagationRule(unsigned SArg,
                         unsigned DArg, bool TaintRet = false) {
      SrcArgs.push_back(SArg);
      DstArgs.push_back(DArg);
      if (TaintRet)
        DstArgs.push_back(ReturnValueIndex);
    }

    TaintPropagationRule(unsigned SArg1, unsigned SArg2,
                         unsigned DArg, bool TaintRet = false) {
      SrcArgs.push_back(SArg1);
      SrcArgs.push_back(SArg2);
      DstArgs.push_back(DArg);
      if (TaintRet)
        DstArgs.push_back(ReturnValueIndex);
    }

    void setSrcArg(ArgVector SrcArgs){ this->SrcArgs = SrcArgs; }
    void setDstArg(ArgVector DstArgs){ this->DstArgs = DstArgs; }
    
    inline void addSrcArg(unsigned A) { SrcArgs.push_back(A); }
    inline void addDstArg(unsigned A)  { DstArgs.push_back(A); }

    inline bool isNull() const { return SrcArgs.empty(); }

    inline bool isDestinationArgument(unsigned ArgNum) const {
      return (std::find(DstArgs.begin(),
                        DstArgs.end(), ArgNum) != DstArgs.end());
    }

    static inline bool isTaintedOrPointsToTainted(const Expr *E,
                                                  ProgramStateRef State,
                                                  CheckerContext &C) {
      return (State->isTainted(E, C.getLocationContext()) || isStdin(E, C) ||
              (E->getType().getTypePtr()->isPointerType() &&
               State->isTainted(getPointedToSymbol(C, E))));
    }

    /// \brief Pre-process a function which propagates taint according to the
    /// taint rule.
    ProgramStateRef process(const CallExpr *CE, CheckerContext &C) const;

  };

  typedef TaintParser::SOURCE SOURCE;
  typedef std::pair<string,TaintPropagationRule> NAMEPROPAGATIONPAIR;
  typedef SmallVector<NAMEPROPAGATIONPAIR, TaintParser::SIZE_METHODS>
                                                                    PROPAGATION;
  typedef TaintParser::DESTINATION DESTINATION;
  typedef TaintParser::FILTER FILTER;


  // Structures to store information retrieved from xml configuration file.
  SOURCE SourceMap;
  PROPAGATION PropagationRuleMap;
  DESTINATION DestinationMap;
  FILTER FilterMap;

  /// Get the propagation rule for a given function.
  TaintPropagationRule getTaintPropagationRule(const FunctionDecl *FDecl,
                                                StringRef Name,
                                                CheckerContext &C) const; 

  class WalkAST : public TaintVisitor {
    public:
      WalkAST(CheckerContext &C, ProgramStateRef State) : TaintVisitor(C, State){}
    private:
      void MarkTaint(Expr* Expr){
        SymbolRef symbol = getPointedToSymbol(C, Expr);
        if (symbol)
          State->addTaint(symbol);
      }
  };
                                              
template<typename... Args>
static void debug(const char* format, Args ... args);
                                               
};

const unsigned CustomTaintChecker::ReturnValueIndex;
const unsigned CustomTaintChecker::InvalidArgIndex;

const char CustomTaintChecker::MsgUncontrolledFormatString[] =
  "Untrusted data is used as a format string "
  "(CWE-134: Uncontrolled Format String)";

    
const char CustomTaintChecker::MsgSanitizeArgs[] =
  "Untrusted data is passed to a custom method. "
  "Sanitize before passing to it";
    
const char CustomTaintChecker::MsgSanitizeSystemArgs[] =
  "Untrusted data is passed to a system call "
  "(CERT/STR02-C. Sanitize data passed to complex subsystems)";

const char CustomTaintChecker::MsgTaintedBufferSize[] =
  "Untrusted data is used to specify the buffer size "
  "(CERT/STR31-C. Guarantee that storage for strings has sufficient space for "
  "character data and the null terminator)";


} // end of anonymous namespace

/// Sets which are used to pass information from call pre-visit instruction
/// to the call post-visit. The values are unsigned integers, which are either
/// ReturnValueIndex, or indexes of the pointer/reference argument, which
/// points to data, which should be tainted on return.
REGISTER_SET_WITH_PROGRAMSTATE(TaintArgsOnPostVisit, unsigned)
REGISTER_SET_WITH_PROGRAMSTATE(UntaintArgsOnPostVisit, unsigned)


// ---------------------------------------- //
//    TaintPropagationRule implementation   //
// ---------------------------------------- //

CustomTaintChecker::TaintPropagationRule
CustomTaintChecker::getTaintPropagationRule( const FunctionDecl *FDecl,
                                             StringRef Name,
                                             CheckerContext &C) const {
  debug("Inside getTaintedPropagationRule(..). Name:%s \n",Name.data());
  // TODO: Currently, we might lose precision here: we always mark a return
  // value as tainted even if it's just a pointer, pointing to tainted data.

  // Check for exact name match for functions without builtin substitutes.
  TaintPropagationRule Rule = llvm::StringSwitch<TaintPropagationRule>(Name)
    .Case("atoi", TaintPropagationRule(0, ReturnValueIndex))
    .Case("atol", TaintPropagationRule(0, ReturnValueIndex))
    .Case("atoll", TaintPropagationRule(0, ReturnValueIndex))
    .Case("getc", TaintPropagationRule(0, ReturnValueIndex))
    .Case("fgetc", TaintPropagationRule(0, ReturnValueIndex))
    .Case("getc_unlocked", TaintPropagationRule(0, ReturnValueIndex))
    .Case("getw", TaintPropagationRule(0, ReturnValueIndex))
    .Case("toupper", TaintPropagationRule(0, ReturnValueIndex))
    .Case("tolower", TaintPropagationRule(0, ReturnValueIndex))
    .Case("strchr", TaintPropagationRule(0, ReturnValueIndex))
    .Case("strrchr", TaintPropagationRule(0, ReturnValueIndex))
    .Case("read", TaintPropagationRule(0, 2, 1, true))
    .Case("pread", TaintPropagationRule(InvalidArgIndex, 1, true))
    .Case("gets", TaintPropagationRule(InvalidArgIndex, 0, true))
    .Case("fgets", TaintPropagationRule(2, 0, true))
    .Case("getline", TaintPropagationRule(2, 0))
    .Case("getdelim", TaintPropagationRule(3, 0))
    .Case("fgetln", TaintPropagationRule(0, ReturnValueIndex))
    .Default(TaintPropagationRule());

  // If the previous case did not find a Propagation Rule for the method, now it
  // has to check the custom rules defined by the user.
  if (Rule.isNull()) {
    for (PROPAGATION::const_iterator
         I = PropagationRuleMap.begin(),
         E = PropagationRuleMap.end(); I != E; ++I) {
      std::pair<StringRef,TaintPropagationRule> pair = *I;
      debug("Inside loop. Checking %s\n", pair.first.data());
      if (pair.first.equals(Name)){
          debug("Propagation Rule found for method %s\n",Name.data());
        Rule = pair.second;
      }
    }
  }

  if (!Rule.isNull())
   return Rule;

  // Check if it's one of the memory setting/copying functions.
  // This check is specialized but faster then calling isCLibraryFunction.
  unsigned BId = 0;
  if ( (BId = FDecl->getMemoryFunctionKind()) )
    switch(BId) {
    case Builtin::BImemcpy:
    case Builtin::BImemmove:
    case Builtin::BIstrncpy:
    case Builtin::BIstrncat:
      return TaintPropagationRule(1, 2, 0, true);
    case Builtin::BIstrlcpy:
    case Builtin::BIstrlcat:
      return TaintPropagationRule(1, 2, 0, false);
    case Builtin::BIstrndup:
      return TaintPropagationRule(0, 1, ReturnValueIndex);

    default:
      break;
    };

  // Process all other functions which could be defined as builtins.
  if (Rule.isNull()) {
    if (C.isCLibraryFunction(FDecl, "snprintf") ||
        C.isCLibraryFunction(FDecl, "sprintf"))
      return TaintPropagationRule(InvalidArgIndex, 0, true);
    else if (C.isCLibraryFunction(FDecl, "strcpy") ||
             C.isCLibraryFunction(FDecl, "stpcpy") ||
             C.isCLibraryFunction(FDecl, "strcat"))
      return TaintPropagationRule(1, 0, true);
    else if (C.isCLibraryFunction(FDecl, "bcopy"))
      return TaintPropagationRule(0, 2, 1, false);
    else if (C.isCLibraryFunction(FDecl, "strdup") ||
             C.isCLibraryFunction(FDecl, "strdupa"))
      return TaintPropagationRule(0, ReturnValueIndex);
    else if (C.isCLibraryFunction(FDecl, "wcsdup"))
      return TaintPropagationRule(0, ReturnValueIndex);
  }

  // Skipping the following functions, since they might be used for cleansing
  // or smart memory copy:
  // - memccpy - copying until hitting a special character.

  return TaintPropagationRule();
}

// ---------------------------------------- //
//     CustomTaintChecker implementation    //
// ---------------------------------------- //

void CustomTaintChecker::checkPreStmt(const CallExpr *CE,
                                       CheckerContext &C)  const{
  // Check for errors first.
  if (checkPre(CE, C))
    return;

  // Check if a custom generator is applied.
  checkGenerators(CE, C);

  // Check if a custom filter is applied.
  checkFilters(CE, C);

  // Add taint second.
  addSourcesPre(CE, C);
}

void CustomTaintChecker::checkPostStmt(const CallExpr *CE,
                                        CheckerContext &C) const {
  if (propagateFromPre(CE, C))
    return;
  propagateFilterFromPre(CE, C);
  addSourcesPost(CE, C);
}

void CustomTaintChecker::checkGenerators(const CallExpr *CE,
                                           CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
    if (!isFDApplicable(FDecl))
    return;

  StringRef Name = C.getCalleeName(FDecl);
  if (Name.empty())
    return;
  debug("In checkGenerators: for method %s\n", Name.data());
  for (SOURCE::const_iterator I = SourceMap.begin(), E = SourceMap.end();
         I != E; ++I) {
    std::pair<StringRef, SmallVector<int, TaintParser::SIZE_ARGS>> pair  = *I;
    debug("In checkGenerators: Checking gen method %s\n", pair.first.data());
    if (Name.equals(pair.first)){
      debug("Generator found. Args size %zu \n", pair.second.size());
      for (llvm::SmallVector<int, TaintParser::SIZE_ARGS>::const_iterator
             J = pair.second.begin(), Z = pair.second.end(); J != Z; ++J) {

        unsigned ArgNum = *J;
        debug("In checkGenerators: Marking argument number %d as tainted.\n",
                ArgNum);

        // Should we mark all arguments as tainted?
        if (ArgNum == InvalidArgIndex) {
          // For all pointer and references that were passed in:
          // If they are not pointing to const data, mark data as tainted.
          // TODO: So far we are just going one level down; ideally we'd need to
          // recurse here.
          for (unsigned int i = 0; i < CE->getNumArgs(); ++i) {
            const Expr *Arg = CE->getArg(i);
            // Process pointer argument.
            const Type *ArgTy = Arg->getType().getTypePtr();
            QualType PType = ArgTy->getPointeeType();
            if ((!PType.isNull() && !PType.isConstQualified())
               || (ArgTy->isReferenceType() &&
               !Arg->getType().isConstQualified()))
              State = State->add<TaintArgsOnPostVisit>(i);
          }
          continue;
        }

        // Should mark the return value?
        if (ArgNum == ReturnValueIndex) {
          State = State->add<TaintArgsOnPostVisit>(ReturnValueIndex);
          continue;
        }

        assert(ArgNum >= 0 && ArgNum < CE->getNumArgs());
        // Mark the given argument.
        State = State->add<TaintArgsOnPostVisit>(ArgNum);
      }
    }
  }
  if (State != C.getState()) {
    debug("In checkGenerators: adding state");
    C.addTransition(State);
  }
}

void CustomTaintChecker::checkFilters(const CallExpr *CE, CheckerContext &C)
                                        const {
  bool filterFound = false;
  ProgramStateRef State = C.getState();
  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  if (!isFDApplicable(FDecl))
    return;

  StringRef Name = C.getCalleeName(FDecl);
  if (Name.empty())
    return;

  for (FILTER::const_iterator I = FilterMap.begin(), E = FilterMap.end();
         I != E; ++I) {
    std::pair<StringRef, SmallVector<int, TaintParser::SIZE_ARGS>> pair  = *I;
    debug("In checkFilters: Checking filter method %s\n", pair.first.data());
    if (Name.equals(pair.first)){
      debug("Filter found. Args size %zu \n", pair.second.size());
      for (llvm::SmallVector<int, TaintParser::SIZE_ARGS>::const_iterator
             J = pair.second.begin(), Z = pair.second.end(); J != Z; ++J) {
                
        unsigned ArgNum = *J;
        debug("In checkFilters: Marking argument number %d as untainted.\n",
                ArgNum);
        assert(ArgNum >= 0 && ArgNum < CE->getNumArgs());
        filterFound = true;
        // Mark the given argument.
        State = State->add<UntaintArgsOnPostVisit>(ArgNum);
      }
    }
  }
  if (filterFound && State)
    C.addTransition(State);
}

void CustomTaintChecker::addSourcesPre(const CallExpr *CE,
                                        CheckerContext &C) const {
  ProgramStateRef State = nullptr;
  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  if (!isFDApplicable(FDecl))
    return;

  StringRef Name = C.getCalleeName(FDecl);
  if (Name.empty())
    return;

  // First, try generating a propagation rule for this function.
  TaintPropagationRule Rule = getTaintPropagationRule(FDecl, Name, C);
  if (!Rule.isNull()) {
    State = Rule.process(CE, C);
    if (!State)
      return;
    C.addTransition(State);
    return;
  }

  // Otherwise, check if we have custom pre-processing implemented.
  FnCheck evalFunction = llvm::StringSwitch<FnCheck>(Name)
    .Case("fscanf", &CustomTaintChecker::preFscanf)
    .Default(nullptr);
  // Check and evaluate the call.
  if (evalFunction)
    State = (this->*evalFunction)(CE, C);
  if (!State)
    return;
  C.addTransition(State);

}

bool CustomTaintChecker::propagateFromPre(const CallExpr *CE,
                                           CheckerContext &C) const {

  // Added just for logging purpose.
  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  StringRef Name = C.getCalleeName(FDecl);
  // --

  debug("In propagateFromPre for method %s\n",Name.data());
  ProgramStateRef State = C.getState();

  // Depending on what was tainted at pre-visit, we determined a set of
  // arguments which should be tainted after the function returns. These are
  // stored in the state as TaintArgsOnPostVisit set.
  TaintArgsOnPostVisitTy TaintArgs = State->get<TaintArgsOnPostVisit>();
  debug("In propagateFromPre: TaintArgs size = %d \n",TaintArgs.getHeight());
  if (TaintArgs.isEmpty())
    return false;
  
  for (llvm::ImmutableSet<unsigned>::iterator
         I = TaintArgs.begin(), E = TaintArgs.end(); I != E; ++I) {
    unsigned ArgNum  = *I;

    // Special handling for the tainted return value.
    if (ArgNum == ReturnValueIndex) {
      debug("In propagateFromPre: taint return argument\n");
      State = State->addTaint(CE, C.getLocationContext());
      continue;
    }

    // The arguments are pointer arguments. The data they are pointing at is
    // tainted after the call.
    if (CE->getNumArgs() < (ArgNum + 1))
      return false;
    
    const Expr* Arg = CE->getArg(ArgNum);
    SymbolRef Sym = getPointedToSymbol(C, Arg);
    if (Sym) {
      debug("In propagateFromPre: taint argument %d of method %s \n", ArgNum,
              Name.data());
      State = State->addTaint(Sym);
    }
    else{
      debug("In propagateFromPre: symbol not found for argument %d of method %s\
              \n",ArgNum, Name.data());
    }
  }

  // Clear up the taint info from the state.
  State = State->remove<TaintArgsOnPostVisit>();

  if (State != C.getState()) {
    debug("In propagateFromPre: State changed, transition added\n");
    C.addTransition(State);
    return true;
  }
  return false;
}

// Is it Funcion Declaration applicable based on its kind?
bool CustomTaintChecker::isFDApplicable(const FunctionDecl* FD) const{
  if (!FD)
    return false;
  if (FD->getKind() == Decl::Function || FD->getKind() == Decl::CXXMethod)
    return true;
  return false;
}

bool CustomTaintChecker::propagateFilterFromPre(const CallExpr *CE,
                                                CheckerContext &C) const {

  // Added just for logging purpose.
  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  StringRef Name = C.getCalleeName(FDecl);
  // --

  debug("In propagateFilterFromPre for method %s\n",Name.data());
  ProgramStateRef State = C.getState();

  // Depending on what was tainted at pre-visit, we determined a set of
  // arguments which should be tainted after the function returns. These are
  // stored in the state as TaintArgsOnPostVisit set.
  UntaintArgsOnPostVisitTy UntaintArgs = State->get<UntaintArgsOnPostVisit>();
  debug("In propagateFilterFromPre: UntaintArgs size = %d \n",
          UntaintArgs.getHeight());
  if (UntaintArgs.isEmpty())
    return false;

  for (llvm::ImmutableSet<unsigned>::iterator
    I = UntaintArgs.begin(), E = UntaintArgs.end(); I != E; ++I) {
    unsigned ArgNum  = *I;

    // Special handling for the tainted return value.
    if (ArgNum == ReturnValueIndex) {
      // For now, if the variable is filtered, it marks the variable as tainted
      // using the tag "UntaintedTag" (see TaintedTag.h)
      State = State->addTaint(CE, C.getLocationContext(), UntaintedTag);
      continue;
    }

    // The arguments are pointer arguments. The data they are pointing at is
    // tainted after the call.
    if (CE->getNumArgs() < (ArgNum + 1))
      return false;

    const Expr* Arg = CE->getArg(ArgNum);
    SymbolRef Sym = getPointedToSymbol(C, Arg);
    if (Sym) {
      debug("Untaint argument %d of method %s \n",ArgNum, Name.data());
      // For now, if the variable is filtered, it marks the variable as tainted
      //using the tag "UntaintedTag" (see TaintedTag.h)
      State = State->addTaint(Sym, UntaintedTag);
    }
    else{
      debug("Symbol not found for argument %d of method %s \n",ArgNum,
              Name.data());
    }
  }
    
  // Clear up the taint info from the state.
  State = State->remove<UntaintArgsOnPostVisit>();
    
  if (State != C.getState()) {
    C.addTransition(State);
    return true;
  }
  return false;
}

void CustomTaintChecker::addSourcesPost(const CallExpr *CE,
                                         CheckerContext &C) const {
  // Define the attack surface.
  // Set the evaluation function by switching on the callee name.
  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  if (!isFDApplicable(FDecl))
    return;

  StringRef Name = C.getCalleeName(FDecl);
  if (Name.empty())
    return;
  FnCheck evalFunction = llvm::StringSwitch<FnCheck>(Name)
    .Case("scanf", &CustomTaintChecker::postScanf)
    // TODO: Add support for vfscanf & family.
    .Case("getchar", &CustomTaintChecker::postRetTaint)
    .Case("getchar_unlocked", &CustomTaintChecker::postRetTaint)
    .Case("getenv", &CustomTaintChecker::postRetTaint)
    .Case("fopen", &CustomTaintChecker::postRetTaint)
    .Case("fdopen", &CustomTaintChecker::postRetTaint)
    .Case("freopen", &CustomTaintChecker::postRetTaint)
    .Case("getch", &CustomTaintChecker::postRetTaint)
    .Case("wgetch", &CustomTaintChecker::postRetTaint)
    .Case("socket", &CustomTaintChecker::postSocket)
    .Default(nullptr);

  // If the callee isn't defined, it is not of security concern.
  // Check and evaluate the call.
  ProgramStateRef State = nullptr;
  if (evalFunction)
    State = (this->*evalFunction)(CE, C);
  if (!State)
    return;

  C.addTransition(State);
}

bool CustomTaintChecker::checkPre(const CallExpr *CE, CheckerContext &C) const{

  // If there is a format argument, it checks if the arg is tainted.
  if (checkUncontrolledFormatString(CE, C))
    return true;

  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  StringRef Name = C.getCalleeName(FDecl);
  
  debug("----In checkPre: for CallExpr name %s----\n", Name.data());
  if (!isFDApplicable(FDecl))
    return false;
  debug("----In checkPre: %s passed fiter----\n ", Name.data());
  
  if (Name.empty())
    return false;

  if (checkCustomDestination(CE, Name, C))
      return true;

  // If the call is a system call. Checks for an specific argument for tainting.
  if (checkSystemCall(CE, Name, C))
    return true;

  // If the call has a buffer size argument. Checks it for tainting.
  if (checkTaintedBufferSize(CE, FDecl, C))
    return true;

  // Maybe this should be placed in another method.
  if (FDecl->getKind() == Decl::CXXMethod){
    WalkAST walkAST(C, C.getState());
    walkAST.Execute(FDecl->getBody());
  }
  return false;
}

SymbolRef CustomTaintChecker::getPointedToSymbol(CheckerContext &C,
                                                  const Expr* Arg) {
  ProgramStateRef State = C.getState();
  SVal AddrVal = State->getSVal(Arg->IgnoreParens(), C.getLocationContext());
  if(AddrVal.isUnknownOrUndef())
    return nullptr;

  Optional<Loc> AddrLoc = AddrVal.getAs<Loc>();
  if (!AddrLoc)
    return nullptr;
    
  const PointerType *ArgTy =
    dyn_cast<PointerType>(Arg->getType().getCanonicalType().getTypePtr());
  SVal Val = State->getSVal(*AddrLoc,
                            ArgTy ? ArgTy->getPointeeType(): QualType());
  Val.dump();
    
  SymbolRef symbol = Val.getAsSymbol();
  if (symbol)
    return symbol;
  // If there is no symbol, and the Svals is a lazyCompoundVal. It tries to get
  // the symbolic base, and then return its symbol.
  else{
    Optional<clang::ento::nonloc::LazyCompoundVal> lazyCompoundVal =
      Val.getAs<clang::ento::nonloc::LazyCompoundVal>();
    if (lazyCompoundVal){
      const SymbolicRegion* symbolicRegion =
        lazyCompoundVal->getRegion()->getSymbolicBase();
      if (symbolicRegion)
        return symbolicRegion->getSymbol();
    }
  }
  return nullptr;
}

ProgramStateRef 
CustomTaintChecker::TaintPropagationRule::process(const CallExpr *CE,
                                                   CheckerContext &C) const {
  // Added just for logging purpose.
    const FunctionDecl *FDecl = C.getCalleeDecl(CE);
    StringRef Name = C.getCalleeName(FDecl);
  //--
       
  ProgramStateRef State = C.getState();

  // Check for taint in arguments.
  bool IsTainted = false;
  for (ArgVector::const_iterator I = SrcArgs.begin(),
                                 E = SrcArgs.end(); I != E; ++I) {
    unsigned ArgNum = *I;

    if (ArgNum == InvalidArgIndex) {
      // Check if any of the arguments is tainted, but skip the
      // destination arguments.
      for (unsigned int i = 0; i < CE->getNumArgs(); ++i) {
        if (isDestinationArgument(i))
          continue;
        if ((IsTainted = isTaintedOrPointsToTainted(CE->getArg(i), State, C)))
          break;
      }
      break;
    }

    if (CE->getNumArgs() < (ArgNum + 1))
      return State;
    if ((IsTainted = isTaintedOrPointsToTainted(CE->getArg(ArgNum), State, C)))
      break;
  }
  if (!IsTainted)
    return State;

  // Mark the arguments which should be tainted after the function returns.
  for (ArgVector::const_iterator I = DstArgs.begin(),
                                 E = DstArgs.end(); I != E; ++I) {
    unsigned ArgNum = *I;

    // Should we mark all arguments as tainted?
    if (ArgNum == InvalidArgIndex) {
      // For all pointer and references that were passed in:
      //   If they are not pointing to const data, mark data as tainted.
      //   TODO: So far we are just going one level down; ideally we'd need to
      //         recurse here.
      for (unsigned int i = 0; i < CE->getNumArgs(); ++i) {
        const Expr *Arg = CE->getArg(i);
        // Process pointer argument.
        const Type *ArgTy = Arg->getType().getTypePtr();
        QualType PType = ArgTy->getPointeeType();
        if ((!PType.isNull() && !PType.isConstQualified())
            || (ArgTy->isReferenceType() && !Arg->getType().isConstQualified()))
          State = State->add<TaintArgsOnPostVisit>(i);
      }
      continue;
    }

    // Should mark the return value?
    if (ArgNum == ReturnValueIndex) {
      State = State->add<TaintArgsOnPostVisit>(ReturnValueIndex);
      continue;
    }

    // Mark the given argument.
    assert(ArgNum < CE->getNumArgs());
      
    debug("In Process(..): Marking as tainted argument %d of method %s.\n",
            ArgNum,Name.data());
    State = State->add<TaintArgsOnPostVisit>(ArgNum);
  }

  return State;
}


// If argument 0 (file descriptor) is tainted, all arguments except for arg 0
// and arg 1 should get taint.
ProgramStateRef CustomTaintChecker::preFscanf(const CallExpr *CE,
                                                   CheckerContext &C) const {
  assert(CE->getNumArgs() >= 2);
  ProgramStateRef State = C.getState();

  // Check is the file descriptor is tainted.
  if (State->isTainted(CE->getArg(0), C.getLocationContext()) ||
      isStdin(CE->getArg(0), C)) {
    // All arguments except for the first two should get taint.
    for (unsigned int i = 2; i < CE->getNumArgs(); ++i)
        State = State->add<TaintArgsOnPostVisit>(i);
    return State;
  }

  return nullptr;
}


// If argument 0(protocol domain) is network, the return value should get taint.
ProgramStateRef CustomTaintChecker::postSocket(const CallExpr *CE,
                                                CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (CE->getNumArgs() < 3)
    return State;

  SourceLocation DomLoc = CE->getArg(0)->getExprLoc();
  StringRef DomName = C.getMacroNameOrSpelling(DomLoc);
  // White list the internal communication protocols.
  if (DomName.equals("AF_SYSTEM") || DomName.equals("AF_LOCAL") ||
      DomName.equals("AF_UNIX") || DomName.equals("AF_RESERVED_36"))
    return State;
  State = State->addTaint(CE, C.getLocationContext());
  return State;
}

ProgramStateRef CustomTaintChecker::postScanf(const CallExpr *CE,
                                                   CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (CE->getNumArgs() < 2)
    return State;

  // All arguments except for the very first one should get taint.
  for (unsigned int i = 1; i < CE->getNumArgs(); ++i) {
    // The arguments are pointer arguments. The data they are pointing at is
    // tainted after the call.
    const Expr* Arg = CE->getArg(i);
        SymbolRef Sym = getPointedToSymbol(C, Arg);
    if (Sym)
      State = State->addTaint(Sym);
  }
  return State;
}

ProgramStateRef CustomTaintChecker::postRetTaint(const CallExpr *CE,
                                                  CheckerContext &C) const {
  return C.getState()->addTaint(CE, C.getLocationContext());
}

bool CustomTaintChecker::isStdin(const Expr *E, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  SVal Val = State->getSVal(E, C.getLocationContext());

  // stdin is a pointer, so it would be a region.
  const MemRegion *MemReg = Val.getAsRegion();

  // The region should be symbolic, we do not know it's value.
  const SymbolicRegion *SymReg = dyn_cast_or_null<SymbolicRegion>(MemReg);
  if (!SymReg)
    return false;

  // Get it's symbol and find the declaration region it's pointing to.
  const SymbolRegionValue *Sm =dyn_cast<SymbolRegionValue>(SymReg->getSymbol());
  if (!Sm)
    return false;
  const DeclRegion *DeclReg = dyn_cast_or_null<DeclRegion>(Sm->getRegion());
  if (!DeclReg)
    return false;

  // This region corresponds to a declaration, find out if it's a global/extern
  // variable named stdin with the proper type.
  if (const VarDecl *D = dyn_cast_or_null<VarDecl>(DeclReg->getDecl())) {
    D = D->getCanonicalDecl();
    if ((D->getName().find("stdin") != StringRef::npos) && D->isExternC())
        if (const PointerType * PtrTy =
              dyn_cast<PointerType>(D->getType().getTypePtr()))
          if (PtrTy->getPointeeType() == C.getASTContext().getFILEType())
            return true;
  }
  return false;
}

static bool getPrintfFormatArgumentNum(const CallExpr *CE,
                                       const CheckerContext &C,
                                       unsigned int &ArgNum) {
  // Find if the function contains a format string argument.
  // Handles: fprintf, printf, sprintf, snprintf, vfprintf, vprintf, vsprintf,
  // vsnprintf, syslog, custom annotated functions.
  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  if (!FDecl)
    return false;
  for (const auto *Format : FDecl->specific_attrs<FormatAttr>()) {
    ArgNum = Format->getFormatIdx() - 1;
    if ((Format->getType()->getName() == "printf") &&
         CE->getNumArgs() > ArgNum)
      return true;
  }

  // Or if a function is named setproctitle (this is a heuristic).
  if (C.getCalleeName(CE).find("setproctitle") != StringRef::npos) {
    ArgNum = 0;
    return true;
  }

  return false;
}

bool CustomTaintChecker::generateReportIfTainted(const Expr *E,
                                                  const char Msg[],
                                                  CheckerContext &C) const {
  assert(E);

  // Check for taint. It only informs if the symbol is tainted with
  // the TaintTagGeneric tag. Ignoring those that are marked as
  // UntaintedTag (filtered symbols).
  ProgramStateRef State = C.getState();
  if (!State->isTainted(getPointedToSymbol(C, E), TaintTagGeneric) &&
      !State->isTainted(E, C.getLocationContext(), TaintTagGeneric))
    return false;

  // Generate diagnostic.
  if (ExplodedNode *N = C.addTransition()) {
      initBugType();
      auto report = llvm::make_unique<BugReport>(*BT, Msg, N);
      report->addRange(E->getSourceRange());
      C.emitReport(std::move(report));
      return true;
  }
  return false;
}

bool CustomTaintChecker::checkUncontrolledFormatString(const CallExpr *CE,
                                                       CheckerContext &C) const{
  // Check if the function contains a format string argument.
  unsigned int ArgNum = 0;
  if (!getPrintfFormatArgumentNum(CE, C, ArgNum))
    return false;

  // If either the format string content or the pointer itself are tainted, warn.
  if (generateReportIfTainted(CE->getArg(ArgNum),
                              MsgUncontrolledFormatString, C))
    return true;
  return false;
}
bool CustomTaintChecker::checkCustomDestination(const CallExpr *CE,
                                                StringRef Name,
                                                CheckerContext &C) const {
  
  debug("In checkCustomDestination: for CE name %s\n",Name.data());
  for (DESTINATION::const_iterator I = DestinationMap.begin(),
       E = DestinationMap.end(); I != E; ++I) {
    std::pair<StringRef,SmallVector<int,TaintParser::SIZE_ARGS>> pair = *I;
    debug("In checkCustomDestination: Checking %s\n",pair.first.data());
    if (pair.first.equals(Name)){
      debug("In checkCustomDestination: destination Rule found for method %s\n",
              Name.data());
      for (SmallVector<int,TaintParser::SIZE_ARGS>::const_iterator I = pair.second.begin(),
           E = pair.second.end(); I != E; ++I) {
        int ArgNum = *I;
        debug("In checkCustomDestination: checking arg %d\n", ArgNum);
        if (generateReportIfTainted(CE->getArg(ArgNum), MsgSanitizeArgs, C))
          return true;
        }
      }
    }
    return false;
}

bool CustomTaintChecker::checkSystemCall(const CallExpr *CE,
                                          StringRef Name,
                                          CheckerContext &C) const {
  // TODO: It might make sense to run this check on demand. In some cases, 
  // we should check if the environment has been cleansed here. We also might 
  // need to know if the user was reset before these calls(seteuid).
  unsigned ArgNum = llvm::StringSwitch<unsigned>(Name)
    .Case("system", 0)
    .Case("popen", 0)
    .Case("execl", 0)
    .Case("execle", 0)
    .Case("execlp", 0)
    .Case("execv", 0)
    .Case("execvp", 0)
    .Case("execvP", 0)
    .Case("execve", 0)
    .Case("dlopen", 0)
    .Default(UINT_MAX);

  if (ArgNum == UINT_MAX || CE->getNumArgs() < (ArgNum + 1))
    return false;

  if (generateReportIfTainted(CE->getArg(ArgNum),
                              MsgSanitizeSystemArgs, C))
    return true;

  return false;
}

// TODO: Should this check be a part of the CString checker?
// If yes, should taint be a global setting?
bool CustomTaintChecker::checkTaintedBufferSize(const CallExpr *CE,
                                                 const FunctionDecl *FDecl,
                                                 CheckerContext &C) const {
  // If the function has a buffer size argument, set ArgNum.
  unsigned ArgNum = InvalidArgIndex;
  unsigned BId = 0;
  if ( (BId = FDecl->getMemoryFunctionKind()) )
    switch(BId) {
    case Builtin::BImemcpy:
    case Builtin::BImemmove:
    case Builtin::BIstrncpy:
      ArgNum = 2;
      break;
    case Builtin::BIstrndup:
      ArgNum = 1;
      break;
    default:
      break;
    };

  if (ArgNum == InvalidArgIndex) {
    if (C.isCLibraryFunction(FDecl, "malloc") ||
        C.isCLibraryFunction(FDecl, "calloc") ||
        C.isCLibraryFunction(FDecl, "alloca"))
      ArgNum = 0;
    else if (C.isCLibraryFunction(FDecl, "memccpy"))
      ArgNum = 3;
    else if (C.isCLibraryFunction(FDecl, "realloc"))
      ArgNum = 1;
    else if (C.isCLibraryFunction(FDecl, "bcopy"))
      ArgNum = 2;
  }

  if (ArgNum != InvalidArgIndex && CE->getNumArgs() > ArgNum &&
      generateReportIfTainted(CE->getArg(ArgNum), MsgTaintedBufferSize, C))
    return true;

  return false;
}

template<typename... Args>
void CustomTaintChecker::debug(const char* format, Args ... args){
  if (DebugFile)
    fprintf(DebugFile, format, args...);
}

void ento::registerCustomTaintChecker(CheckerManager &mgr) {
  CustomTaintChecker* checker = mgr.registerChecker<CustomTaintChecker>();
  string ConfigurationFilePath =
    mgr.getAnalyzerOptions().getOptionAsString("ConfigurationFile", "", checker);
  string DebugFilePath =
    mgr.getAnalyzerOptions().getOptionAsString("DebugFile", "", checker);
  checker -> initialization(ConfigurationFilePath, DebugFilePath);
}
