import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;
import net.sf.javabdd.*;
import org.apache.log4j.Logger;
import tau.smlab.syntech.spectragameinput.SpectraInputProviderNoIDE;
import tau.smlab.syntech.gameinput.model.GameInput;
import tau.smlab.syntech.gameinput.kind.PitermanSyntacticReduction;
import tau.smlab.syntech.gameinputtrans.TranslationProvider;
import tau.smlab.syntech.gameinputtrans.translator.DefaultTranslators;
import tau.smlab.syntech.bddgenerator.BDDGenerator;
import tau.smlab.syntech.bddgenerator.BDDGenerator.TraceInfo;
import tau.smlab.syntech.gamemodel.*;
import tau.smlab.syntech.games.gr1.GR1SeparatedGame;
import tau.smlab.syntech.jtlv.*;

/** Preparation artifact. Never run without the reviewed bounded supervisor and
 * exact new root GO. There are no runnable gate-only jobs. A solve job rebuilds
 * one model, rechecks its complete identity against its adopted gate model,
 * and makes exactly one raw four-fixed-point call, with no extraction.
 */
public final class ExactBSameSolverDiagnostic {
  static final String H="~envHelp";
  static void need(boolean value,String message){ReleasedKindJobProducer.require(value,message);}
  static JsonObject read(Path p)throws Exception{return JsonParser.parseString(Files.readString(p)).getAsJsonObject();}
  static JsonObject obj(Object x){return RetainedBoundaryExportOnly.object(x);}
  static Path pinned(JsonObject pin)throws Exception{return RetainedBoundaryExportOnly.pinned(pin);}
  static Map<String,Object> pin(Path p)throws Exception{
    byte[] b=Files.readAllBytes(p);return ReleasedKindJobProducer.m("path",p.toAbsolutePath().toString(),"bytes",b.length,"sha256",ReleasedKindJobProducer.sha(b));
  }
  static void verifyPinEquals(JsonObject a,JsonObject b,String label)throws Exception{
    Path pa=pinned(a),pb=pinned(b);
    need(a.get("bytes").getAsLong()==b.get("bytes").getAsLong()&&a.get("sha256").getAsString().equals(b.get("sha256").getAsString())&&Files.isSameFile(pa,pb),label);
  }
  static JsonObject authorization(Path path,String digest,String stage,Path root)throws Exception{
    need(digest.matches("[0-9a-f]{64}"),"Authorization digest syntax");
    need(ReleasedKindJobProducer.sha(Files.readAllBytes(path)).equals(digest),"Exact root authorization bytes");
    JsonObject a=read(path);need(a.get("schema").getAsString().equals("v71-r9-distinct-pair-root-authorization-v1"),"Root authorization schema");
    need(stage.equals("solve_unchanged")||stage.equals("solve_S01_release"),"R9 has no runnable native arm gates or saved cross");
    String wanted="GO_DISTINCT_PAIR_SOLVES_ONLY";
    need(a.get("status").getAsString().equals(wanted),"Correct GO phase");
    Set<String> permitted=new HashSet<>();for(JsonElement e:a.getAsJsonArray("authorized_stages"))need(permitted.add(e.getAsString()),"Distinct authorized stages");need(permitted.equals(new HashSet<>(Arrays.asList("solve_unchanged","solve_S01_release")))&&permitted.contains(stage),"Exactly the new pair is authorized");
    need(a.get("protocol_identity").getAsString().equals(AdoptedV5Evidence.PROTOCOL),"Current R9 protocol");
    if(a.has("expires_utc"))need(java.time.Instant.now().isBefore(java.time.Instant.parse(a.get("expires_utc").getAsString())),"Unexpired current GO");
    Path plan=pinned(a.getAsJsonObject("plan")),freeze=pinned(a.getAsJsonObject("input_freeze"));
    need(Files.isSameFile(plan,root.resolve("PLAN.json"))&&Files.isSameFile(freeze,root.resolve("INPUT_FREEZE.json")),"This preparation's plan and freeze");
    JsonObject p=read(plan);need(p.get("schema").getAsString().equals("v71-r9-distinct-pair-plan-v1"),"Plan schema");
    need(p.getAsJsonObject("stages").keySet().equals(new HashSet<>(Arrays.asList("solve_unchanged","solve_S01_release")))&&p.getAsJsonObject("stages").has(stage),"Only two fresh solve stages");
    verifyPinEquals(a.getAsJsonObject("prior_gate_bundle"),p.getAsJsonObject("prior_gate_bundle"),"GO binds reviewed prior gate bundle");
    verifyPinEquals(a.getAsJsonObject("adopted_v5_evidence"),p.getAsJsonObject("adopted_v5_evidence"),"GO binds current historical evidence bridge");
    need(Files.isSameFile(pinned(a.getAsJsonObject("adopted_v5_evidence")),root.resolve("ADOPTED_V5_EVIDENCE.json")),"This preparation's bridge");
    JsonObject lock=read(root.resolve("RUN_LOCK.json")),reservation=read(root.resolve("runs").resolve(stage).resolve("RESERVATION.json"));
    for(Map.Entry<String,JsonElement> entry:lock.entrySet())need(entry.getValue().equals(reservation.get(entry.getKey())),"Exact one-shot supervisor reservation");
    need(lock.get("stage").getAsString().equals(stage)&&lock.get("authorization_sha256").getAsString().equals(digest)
      &&reservation.get("attempt").getAsInt()==1&&reservation.get("maximum_concurrency").getAsInt()==1,"This stage and GO reservation");
    need(ProcessHandle.current().parent().isPresent()&&ProcessHandle.current().parent().get().pid()==lock.get("supervisor_pid").getAsLong(),"Only the owning supervisor may launch this native process");
    return a;
  }
  static JsonObject gateAdoption(JsonObject auth,JsonObject authPin,Path root,String stage)throws Exception{
    return AdoptedV5Evidence.adoption(auth,authPin,root,stage);
  }
  static void selectReceipt(Path p)throws Exception{Files.createDirectories(p.getParent());ReleasedKindJobProducer.receipt=p;}
  static JsonObject saveModel(GameModel gm,Set<String> pe,Set<String> ps,Object parsed,Object translated,Path input,Path folder)throws Exception{
    selectReceipt(folder.resolve("MODEL_CONTEXT.json"));
    Map<String,Object> m=ReleasedKindJobProducer.modelExport(gm,pe,ps,parsed,translated,input);
    ReleasedKindJobProducer.writeJson("model.json",m);return obj(m);
  }
  static BDD edgeDomain(GameModel gm){
    return ReleasedKindJobProducer.domain(gm.getEnv(),false).andWith(ReleasedKindJobProducer.domain(gm.getSys(),false)).andWith(ReleasedKindJobProducer.domain(gm.getEnv(),true)).andWith(ReleasedKindJobProducer.domain(gm.getSys(),true));
  }
  static void completeIdentity(GameModel gm,JsonObject prior,JsonObject fresh,Path priorDir,String prefix)throws Exception{
    Map<Integer,Integer> map=RetainedBoundaryExportOnly.fieldMap(prior,fresh,false);
    need(prior.get("fields").equals(fresh.get("fields"))&&prior.get("bdd_variable_order").equals(fresh.get("bdd_variable_order")),"Exact field encodings/order, no adaptive remapping");
    BDD typed=ReleasedKindJobProducer.domain(gm.getEnv(),false).andWith(ReleasedKindJobProducer.domain(gm.getSys(),false));BDD edge=edgeDomain(gm);
    JsonObject bs=prior.getAsJsonObject("original_bdds");
    try{
      RetainedBoundaryExportOnly.compareSaved(prefix+"_rhoE",gm.getEnv().trans(),bs.getAsJsonObject("rhoE"),priorDir,map,edge);
      RetainedBoundaryExportOnly.compareSaved(prefix+"_rhoS",gm.getSys().trans(),bs.getAsJsonObject("rhoS"),priorDir,map,edge);
      RetainedBoundaryExportOnly.compareSaved(prefix+"_thetaE",gm.getEnv().initial(),bs.getAsJsonObject("thetaE"),priorDir,map,typed);
      RetainedBoundaryExportOnly.compareSaved(prefix+"_thetaS",gm.getSys().initial(),bs.getAsJsonObject("thetaS"),priorDir,map,typed);
      for(String k:new String[]{"domain","domain_ENV_next","domain_SYS_next"}){
        BDD actual=k.equals("domain")?typed.id():ReleasedKindJobProducer.domain(k.equals("domain_ENV_next")?gm.getEnv():gm.getSys(),true);
        BDD mask=Env.TRUE();try{RetainedBoundaryExportOnly.compareSaved(prefix+"_"+k,actual,bs.getAsJsonObject(k),priorDir,map,mask);}finally{actual.free();mask.free();}
      }
      for(String owner:new String[]{"ENV","SYS"}){
        PlayerModule module=owner.equals("ENV")?gm.getEnv():gm.getSys();JsonArray js=prior.getAsJsonObject("original_justices").getAsJsonArray(owner);
        need(module.justiceNum()==js.size()&&js.size()==(owner.equals("ENV")?1:2),"Exact nonempty justice counts");
        for(int i=0;i<js.size();i++)RetainedBoundaryExportOnly.compareSaved(prefix+"_"+owner+"_justice_"+i,module.justiceAt(i),js.get(i).getAsJsonObject(),priorDir,map,typed);
      }
    }finally{typed.free();edge.free();}
  }
  static void checkDispatch(GameModel gm,String label)throws Exception{
    need(gm.getEnv().getTransFuncType()==PlayerModule.TransFuncType.SINGLE_FUNC&&gm.getSys().getTransFuncType()==PlayerModule.TransFuncType.SINGLE_FUNC,"Both actual modules SINGLE_FUNC");
    Field f=PlayerModule.class.getDeclaredField("simConjunctAbs");f.setAccessible(true);
    need(!f.getBoolean(gm.getEnv())&&!f.getBoolean(gm.getSys()),"Both actual SCA settings false");
    ReleasedKindJobProducer.out.put(label,ReleasedKindJobProducer.m("ENV_transFunc",gm.getEnv().getTransFuncType().toString(),"SYS_transFunc",gm.getSys().getTransFuncType().toString(),"ENV_simConjunctAbs",f.getBoolean(gm.getEnv()),"SYS_simConjunctAbs",f.getBoolean(gm.getSys()),"operator_paths","yieldStatesOrig and predSingleTrans; no decomposed partitions used"));
  }
  static void intervene(GameModel gm,boolean release)throws Exception{
    checkDispatch(gm,"dispatch_before_intervention");
    BDD before=gm.getSys().trans().id(),edge=edgeDomain(gm),cube=RetainedBoundaryExportOnly.helperCube(0,1),add=cube.and(edge);
    try{
      BDD expected=release?before.or(add):before.id();
      if(release)gm.getSys().trans().orWith(add.id());
      need(gm.getSys().trans().equals(expected),"Exactly old SYS relation OR typed S01, no other mutation");expected.free();
      BDD delta=before.xor(gm.getSys().trans()),notAfter=gm.getSys().trans().not(),notCube=cube.not(),removed=before.and(notAfter);
      BDD outside=delta.and(notCube);notAfter.free();notCube.free();
      need(removed.isZero()&&outside.isZero(),"Only SYS relaxation in S01");
      if(release)need(!delta.isZero(),"Actual nonempty S01 intervention");else need(delta.isZero(),"Control SYS unchanged");
      Map<String,Object> qs=new LinkedHashMap<>();
      for(int h=0;h<2;h++)for(int hp=0;hp<2;hp++){
        String name=""+h+hp;BDD q=RetainedBoundaryExportOnly.helperCube(h,hp),a=before.restrict(q),b=gm.getSys().trans().restrict(q),mask=edge.restrict(q);
        boolean same=a.equals(b);if(!name.equals("01")||!release)need(same,"All nonintervened SYS quadrants identical");
        if(name.equals("01")&&release){BDD bt=b.and(mask);need(bt.equals(mask),"New S01 is complete on typed domain");bt.free();}
        if(name.equals("11"))need(a.isOne()&&b.isOne(),"Exact B has no retained S11 safety/AUX duty");
        qs.put(name,ReleasedKindJobProducer.m("unchanged",same,"after",ReleasedKindJobProducer.snapshot("arm_S"+name,b)));
        a.free();b.free();mask.free();q.free();
      }
      ReleasedKindJobProducer.out.put("intervention",ReleasedKindJobProducer.m("arm",release?"S01_release":"unchanged","only_full_SYS_relation_changed",release,"typed_S01_release",release,"removed_edges_zero",removed.isZero(),"xor_outside_S01_zero",outside.isZero(),"delta_zero",delta.isZero(),"delta",ReleasedKindJobProducer.snapshot("SYS_relation_delta",delta),"SYS_quadrants",qs));
      delta.free();removed.free();outside.free();
    }finally{before.free();edge.free();cube.free();add.free();}
  }
  static void preservedParts(GameModel gm,JsonObject baseline,JsonObject fresh,Path baseDir)throws Exception{
    Map<Integer,Integer> map=RetainedBoundaryExportOnly.fieldMap(baseline,fresh,false);BDD typed=ReleasedKindJobProducer.domain(gm.getEnv(),false).andWith(ReleasedKindJobProducer.domain(gm.getSys(),false)),edge=edgeDomain(gm);
    try{
      for(String k:new String[]{"thetaE","thetaS","rhoE","domain","domain_ENV_next","domain_SYS_next"}){
        BDD actual=k.equals("thetaE")?gm.getEnv().initial().id():k.equals("thetaS")?gm.getSys().initial().id():k.equals("rhoE")?gm.getEnv().trans().id():k.equals("domain")?typed.id():ReleasedKindJobProducer.domain(k.equals("domain_ENV_next")?gm.getEnv():gm.getSys(),true);
        try{RetainedBoundaryExportOnly.compareSaved("preserved_"+k,actual,baseline.getAsJsonObject("original_bdds").getAsJsonObject(k),baseDir,map,k.equals("rhoE")?edge:typed);}finally{actual.free();}
      }
      for(String owner:new String[]{"ENV","SYS"}){PlayerModule mod=owner.equals("ENV")?gm.getEnv():gm.getSys();JsonArray js=baseline.getAsJsonObject("original_justices").getAsJsonArray(owner);need(js.size()==mod.justiceNum(),"Justice count unchanged");for(int i=0;i<js.size();i++)RetainedBoundaryExportOnly.compareSaved("preserved_"+owner+"_justice_"+i,mod.justiceAt(i),js.get(i).getAsJsonObject(),baseDir,map,typed);}
    }finally{typed.free();edge.free();}
  }
  public static void main(String[] args)throws Exception{
    if(args.length!=7)throw new IllegalArgumentException("config output origins stage arm root-authorization root-authorization-sha256");
    Path config=Paths.get(args[0]).toAbsolutePath(),out=Paths.get(args[1]).toAbsolutePath(),origins=Paths.get(args[2]).toAbsolutePath(),root=config.getParent();String stage=args[3],arm=args[4];
    need(arm.equals("unchanged")||arm.equals("S01_release"),"Exactly two fixed arms");boolean solve=stage.equals("solve_"+arm);need(solve,"Only the two fresh solve stages are runnable");
    need(Files.isSameFile(origins,root.resolve("origins.properties")),"Fixed new origins file");
    need(out.equals(root.resolve("runs").resolve(stage).resolve("native_result/RESULT.json")),"Fixed new output path");need(!Files.exists(out),"No result overwrite");
    JsonObject auth=authorization(Paths.get(args[5]),args[6],stage,root),adoption=gateAdoption(auth,obj(pin(Paths.get(args[5]))),root,stage);
    JsonObject c=read(config);need(c.get("schema").getAsString().equals("v71-r7-two-arm-B-config-v1")&&c.get("id").getAsString().equals("B_NEW_POINT_R2404"),"Exact B config");
    Path input=pinned(c.getAsJsonObject("input")),projected=pinned(c.getAsJsonObject("projected_source")),priorFile=pinned(c.getAsJsonObject("prior_helper_model")),sourceFile=pinned(c.getAsJsonObject("prior_source_model")),exactFile=pinned(c.getAsJsonObject("prior_exact_model"));pinned(c.getAsJsonObject("prior_exact_gate_adoption"));
    JsonObject prior=read(priorFile),source=read(sourceFile),exact=read(exactFile);
    byte[] wrapper=Files.readAllBytes(input),prefix=Files.readAllBytes(projected);need(wrapper.length==2026&&prefix.length==1902&&Arrays.equals(Arrays.copyOf(wrapper,prefix.length),prefix),"Exact B wrapper and update projection");need(ReleasedKindJobProducer.sha(wrapper).equals("212309df489c3ddc7bf7ec6a750aed2d0da4fb7e26995e5ee3a0405c9897e1d5"),"Fixed B bytes");
    selectReceipt(out);ReleasedKindJobProducer.fixtureId="OBSTACLE_NEW__point_r2404_same_solver";ReleasedKindJobProducer.caseId="B_NEW_POINT_R2404";ReleasedKindJobProducer.variant=arm;ReleasedKindJobProducer.start=System.nanoTime();ReleasedKindJobProducer.startHeapSampler();
    BoundedDiagnosticPrintStream capture=new BoundedDiagnosticPrintStream(System.out,out.resolveSibling("CAPTURE_RECEIPT.json"),68719476736L,67108864L);System.setOut(capture);
    Runtime.getRuntime().addShutdownHook(new Thread(()->{try{capture.finish();}catch(Exception e){e.printStackTrace(System.err);}},"bounded-exact-capture"));
    Map<String,Object> r=ReleasedKindJobProducer.out;r.put("schema","v71-r9-exact-B-same-observer-pair-result-v1");r.put("protocol_identity",AdoptedV5Evidence.PROTOCOL);r.put("capture_limits",ReleasedKindJobProducer.m("raw_stdout_observed_bytes",68719476736L,"encoded_stdout_bytes",67108864L));r.put("status","RUNNING");r.put("requested_stage",stage);r.put("arm",arm);r.put("authorization",pin(Paths.get(args[5])));r.put("config",pin(config));r.put("input",pin(input));
    for(String k:new String[]{"model_generation_attempts","model_generations","raw_call_entry_attempts","raw_four_fixed_point_calls_returned","syntactic_reduction_calls","semantic_reduction_calls","solver_constructions","raw_four_fixed_point_calls","native_strict_solver_calls","winning_region_computations","controller_extraction_calls"})r.put(k,0);
    r.put("accounting_finalized",false);r.put("model_generation_call_dispatched",false);r.put("raw_call_dispatch_recorded",false);
    r.put("accounting_scope","A reservation consumes one attempt. BEGIN checkpoints record durable intent; adjacent local dispatch flags are published at return/finalization. A hard stop before finalization makes unobserved dispatch/return indeterminate, never refundable or proven zero.");
    r.put("source_or_monitor_reset",false);r.put("G_and_A_normalization",false);r.put("GUI_execution",false);r.put("provider_scope","Private NoIDE provider, same pinned released translator/classes; no historical GUI object or live dispatch identity claimed");r.put("controller_memory","not extracted or transferred");
    r.put("runtime",ReleasedKindJobProducer.m("java_version",System.getProperty("java.version"),"java_runtime_version",System.getProperty("java.runtime.version"),"java_vm_name",System.getProperty("java.vm.name"),"java_vendor",System.getProperty("java.vendor"),"java_home",System.getProperty("java.home")));
    r.put("harness_class",ReleasedKindJobProducer.identity(ExactBSameSolverDiagnostic.class));r.put("helper_class",ReleasedKindJobProducer.identity(RetainedBoundaryExportOnly.class));r.put("serializer_class",ReleasedKindJobProducer.identity(ReleasedKindJobProducer.class));r.put("capture_class",ReleasedKindJobProducer.identity(BoundedDiagnosticPrintStream.class));
    Logger.getRootLogger().addAppender(new ReleasedKindJobProducer.ValidationLogWatch());GameModel gm=null;BDDFactory factory=null;GR1SeparatedGame solver=null;int exit=0;boolean modelDispatched=false,rawDispatched=false,rawReturned=false;
    try{
      ReleasedKindJobProducer.checkOrigins(origins);ReleasedKindJobProducer.checkpoint("PARSE_FIXED_B");
      GameInput gi=new SpectraInputProviderNoIDE().getGameInput(input.toString());ReleasedKindJobProducer.validationHealthy();Object parsed=ReleasedKindJobProducer.inventory(gi);r.put("parsed_before_reduction",parsed);
      need(RetainedBoundaryExportOnly.noninitialInventory(obj(parsed),true).equals(RetainedBoundaryExportOnly.noninitialInventory(source.getAsJsonObject("source_inventory").getAsJsonObject("parsed"),false)),"Noninitial source inventory unchanged");
      need(gi.getAux().getVars().isEmpty()&&gi.getAux().getConstraints().isEmpty(),"No source AUX");
      PitermanSyntacticReduction.doReduction(gi);r.put("syntactic_reduction_calls",1);r.put("parsed_after_reduction",ReleasedKindJobProducer.inventory(gi));
      TranslationProvider.translate(gi,DefaultTranslators.getDefaultTranslators());ReleasedKindJobProducer.validationHealthy();ReleasedKindJobProducer.auditTranslated(gi);Object translated=ReleasedKindJobProducer.inventory(gi);r.put("translated_inventory",translated);need(gi.getAux().getVars().isEmpty()&&gi.getAux().getConstraints().isEmpty(),"No translated AUX");
      BDDPackage.setCurrPackage(BDDPackage.JTLV,BDDPackage.BBDPackageVersion.DEFAULT);Env.disableReorder();BDD one=Env.TRUE();factory=one.getFactory();one.free();r.put("observed_backend",ReleasedKindJobProducer.backend());
      r.put("model_generation_attempts",1);ReleasedKindJobProducer.checkpoint("GENERATE_ONE_MODEL");modelDispatched=true;gm=BDDGenerator.generateGameModel(gi,TraceInfo.NONE,false,PlayerModule.TransFuncType.SINGLE_FUNC);r.put("model_generations",1);r.put("model_generation_call_dispatched",true);ReleasedKindJobProducer.checkpoint("ONE_MODEL_GENERATION_RETURNED");gm.getEnv().setSCA(false);gm.getSys().setSCA(false);checkDispatch(gm,"dispatch_after_generation");
      Set<String> pe=new LinkedHashSet<>(Arrays.asList("obstacle[0]","obstacle[1]","obsWait",H)),ps=new LinkedHashSet<>(Arrays.asList("robot[0]","robot[1]"));
      Path baseDir=out.getParent().resolve("baseline"),armDir=out.getParent().resolve("arm");JsonObject baseline=saveModel(gm,pe,ps,parsed,translated,input,baseDir);r.put("baseline_model",pin(baseDir.resolve("model.json")));
      need(ReleasedKindJobProducer.carrierSize.intValueExact()==12544,"Exact typed six-field carrier");need(!Env.hasVars(gm.getEnv().trans(),gm.getSys().modulePrimeVars()),"ENV next-SYS independence");
      RetainedBoundaryExportOnly.compareNoninitial(gm,prior,source,baseline,priorFile.getParent(),sourceFile.getParent());RetainedBoundaryExportOnly.pointInitializers(gm);completeIdentity(gm,exact,baseline,exactFile.getParent(),"baseline_exact_old_B");r.put("baseline_matches_old_adopted_B",true);
      selectReceipt(armDir.resolve("MODEL_CONTEXT.json"));intervene(gm,arm.equals("S01_release"));JsonObject finalModel=saveModel(gm,pe,ps,parsed,translated,input,armDir);r.put("arm_model",pin(armDir.resolve("model.json")));preservedParts(gm,baseline,finalModel,baseDir);RetainedBoundaryExportOnly.pointInitializers(gm);r.put("all_preserved_parts_equal",true);
      selectReceipt(out);checkDispatch(gm,"dispatch_before_completion_or_solve");
      if(solve){
        String gate="gate_"+arm;JsonObject gateResult=read(pinned(adoption.getAsJsonObject("gate_results").getAsJsonObject(gate)));
        need(gateResult.get("status").getAsString().equals("PASS_ARM_GATE_NO_SOLVE")&&gateResult.get("raw_four_fixed_point_calls").getAsInt()==0,"This arm gate completed before solve");
        Path gateModel=pinned(gateResult.getAsJsonObject("arm_model"));completeIdentity(gm,read(gateModel),finalModel,gateModel.getParent(),"adopted_arm_before_solver");r.put("adopted_gate_model",pin(gateModel));r.put("gate_adoption",pin(pinned(auth.getAsJsonObject("gate_adoption"))));
        ReleasedKindJobProducer.checkpoint("ALL_GATES_RECHECKED_BEFORE_SOLVER_CONSTRUCTION");
        solver=new GR1SeparatedGame(gm);r.put("solver_constructions",1);need(gm.getEnv().justiceNum()==1&&gm.getSys().justiceNum()==2,"Constructor did not add or alter justice roster");checkDispatch(gm,"dispatch_after_solver_construction");
        completeIdentity(gm,read(gateModel),finalModel,gateModel.getParent(),"adopted_arm_after_solver_constructor");r.put("solver_class",ReleasedKindJobProducer.identity(solver.getClass()));need(solver.getClass()==GR1SeparatedGame.class,"Exact released solver class");
        r.put("raw_call_entry_attempts",1);ReleasedKindJobProducer.checkpoint("ONE_RAW_FOUR_FP_CALL_BEGIN");rawDispatched=true;boolean answer=solver.checkRealizability();rawReturned=true;r.put("raw_four_fixed_point_calls",1);r.put("winning_region_computations",1);r.put("raw_four_fixed_point_calls_returned",1);r.put("raw_call_dispatch_recorded",true);r.put("realizable",answer);r.put("status","PASS_ONE_RAW_FOUR_FP_RESULT");ReleasedKindJobProducer.checkpoint("ONE_RAW_FOUR_FP_CALL_RETURNED");
      }else{r.put("status","PASS_ARM_GATE_NO_SOLVE");ReleasedKindJobProducer.checkpoint("ARM_GATE_DONE_NO_SOLVER");}
      ReleasedKindJobProducer.checkOrigins(origins);ReleasedKindJobProducer.validationHealthy();
    }catch(Throwable e){exit=2;r.put("status","UNKNOWN_DIAGNOSTIC_EXCEPTION");r.put("failed_stage",ReleasedKindJobProducer.stage);r.put("exception",e.toString());StringWriter sw=new StringWriter();e.printStackTrace(new PrintWriter(sw));r.put("traceback",sw.toString());
    }finally{
      r.put("model_generation_call_dispatched",modelDispatched);r.put("raw_call_dispatch_recorded",rawDispatched);r.put("raw_four_fixed_point_calls",rawDispatched?1:0);r.put("winning_region_computations",rawDispatched?1:0);r.put("raw_four_fixed_point_calls_returned",rawReturned?1:0);r.put("accounting_finalized",true);
      selectReceipt(out);
      try{if(solver!=null)solver.free();if(gm!=null)gm.free();if(factory!=null)factory.done();r.put("teardown","COMPLETED");}catch(Throwable e){exit=3;r.put("status","UNKNOWN_DIAGNOSTIC_TEARDOWN");r.put("teardown_exception",e.toString());}
      if(ReleasedKindJobProducer.heapSampler!=null)ReleasedKindJobProducer.heapSampler.cancel();
      try{capture.finish();JsonObject cr=read(out.resolveSibling("CAPTURE_RECEIPT.json"));need(cr.get("capture_complete").getAsBoolean()&&!cr.get("cap_reached").getAsBoolean(),"Lossless bounded stdout completed");r.put("capture_receipt",pin(out.resolveSibling("CAPTURE_RECEIPT.json")));}catch(Throwable e){exit=4;r.put("status","UNKNOWN_DIAGNOSTIC_CAPTURE");r.put("capture_exception",e.toString());}
      ReleasedKindJobProducer.checkpoint("PROCESS_FINISHED");
    }
    System.exit(exit);
  }
}
