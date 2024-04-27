package com.anjia.unidbgserver.service;

import com.anjia.unidbgserver.config.UnidbgProperties;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.EmulatorBuilder;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.VaList;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.jni.ProxyClassFactory;
import com.github.unidbg.linux.file.SimpleFileIO;
import com.github.unidbg.memory.Memory;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import org.apache.commons.io.FileUtils;
import org.springframework.core.io.ClassPathResource;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class AoBiShield extends AbstractJni implements IOResolver<AndroidFileIO> {
    private static final String APK_PATH = "data/aobi/base.apk";
    private static final String APK_ROOT_PATH = "/data/app/com.leiting.aobi-pfYRsZvQQKMTaRS0sZlvHA==/base.apk";
    private static final String APP_PACKAGE_NAME = "com.leiting.aobi";
    private static final String CmdLine_PATH = "data/aobi/root/proc/self/cmdline";
    private static final String MAPS_PATH = "data/aobi/root/proc/self/maps";
    private static final String SO_PATH = "data/aobi/lib/arm64-v8a/libNetHTProtect.so";
    private final File File_APK;
    private final File File_cmdline;
    private final File File_maps;
    private final DvmClass JNIFactory;
    private final AndroidEmulator emulator;
    private boolean hasinit = false;
    private final VM vm;

    @SneakyThrows
    AoBiShield(UnidbgProperties unidbgProperties) {
        EmulatorBuilder<AndroidEmulator> builder = AndroidEmulatorBuilder.for64Bit().setProcessName(APP_PACKAGE_NAME);
        if (unidbgProperties != null && unidbgProperties.isDynarmic()) {
            builder.addBackendFactory(new DynarmicFactory(true));
        }
        emulator = builder.build();
        emulator.getSyscallHandler().addIOResolver(this);
        Memory memory = this.emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        File_cmdline = openfile(CmdLine_PATH);
        File_maps = openfile(MAPS_PATH);
        File_APK = openfile(APK_PATH);
        vm = emulator.createDalvikVM(File_APK);
        vm.setVerbose(true);
        File soLibFile = openfile(SO_PATH);
        DalvikModule dm = vm.loadLibrary(soLibFile, true);
        this.vm.setJni(this);
        dm.callJNI_OnLoad(emulator);
        JNIFactory = vm.resolveClass("com/netease/htprotect/factory/JNIFactory");
    }

    public File openfile(String path) throws IOException {
        File soLibFile = new File(System.getProperty("java.io.tmpdir"), path);
        if (!soLibFile.exists()) {
            FileUtils.copyInputStreamToFile(new ClassPathResource(path).getInputStream(), soLibFile);
        }
        return soLibFile;
    }

    public void destroy() throws IOException{
        emulator.close();
    }

    public void htp_init(String appid, String game_key, int serverType) {
        DvmObject<?> context = vm.resolveClass("android/content/Context").newObject(null);
        JNIFactory.callStaticJniMethodObject(emulator, "hccd63688a790ca65(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ILcom/netease/htprotect/HTPCallback;)V", context, appid, game_key, serverType, null);
        hasinit = true;
    }

    public int doSomeWork(byte[] bArr) {
        if (bArr == null) {
            return 1;
        }
        int i = (bArr[1] & 255) << 8;
        return (bArr[0] & 255) | i | ((bArr[3] & 255) << 24) | ((bArr[2] & 255) << 16);
    }

    //htp_safeCommToServer(bArr, i2, 0, false);//加密
    //htp_safeCommToServer(bArr, i2, i3, true);//解密
    public byte[] htp_safeCommToServer(byte[] bArr, int i, int i2, boolean dec) {
        if (!hasinit) {
            htp_init("A000416870", "9b4650ec01545f2a7516bc151493d0f6", 1);
        }
        ByteArray array = JNIFactory.callStaticJniMethodObject(emulator, "r25d273c7ad4065c3([BIIZ)[B", bArr, i, i2, dec);
        return (byte[]) array.getValue();
    }

    public String safeCommToServer(String p0) {
        byte[] hexData = new byte[]{67,103,89,49,90,50,57,120,97,109,103,61};
        byte[] bytes = htp_safeCommToServer(hexData,0 ,0,false);
        if  (doSomeWork(bytes) == 0) {
            byte[] encBytes = new byte[bytes.length - 4];
            System.arraycopy(bytes, 4, encBytes, 0, bytes.length - 4);
            return new BigInteger(1, encBytes).toString(16).toUpperCase();
        }
        return "";
    }

    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        return "java/lang/Class->forName(Ljava/lang/String;)Ljava/lang/Class;".equals(signature) ? vm.resolveClass(vaList.getObjectArg(0).toString()) : super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    public void callVoidMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (!"Ljava/lang/reflect/Field->setAccessible(Z)V".equals(signature)) {
            super.callVoidMethodV(vm, dvmObject, signature, vaList);
        }
    }

    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "java/lang/Class->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;":
                return vm.resolveClass("Ljava/lang/reflect/Field").newObject(null);
            case "java/lang/Class->getClass()Ljava/lang/Class;":
                return vm.resolveClass("java/lang/Class");
            case "java/lang/Class->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;":
            case "Ljava/lang/reflect/Field->get(Ljava/lang/Object;)Ljava/lang/Object;":
                return vm.resolveClass("Ljava/lang/Object;");
            case "java/lang/Class->getPackageResourcePath()Ljava/lang/String;":
                return new StringObject(vm, APK_ROOT_PATH);
            case "java/lang/Class->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;":
                return vm.resolveClass("Ljava/lang/reflect/Method;");
            default:
                return super.callObjectMethodV(vm, dvmObject, signature, vaList);
        }
    }

    public FileResult<AndroidFileIO> resolve(Emulator emulator, String pathname, int oflags) {
        if ("/proc/self/cmdline".equals(pathname)) {
            return FileResult.success(new SimpleFileIO(oflags, File_cmdline, pathname));
        }
        if ("/proc/self/maps".equals(pathname)) {
            return FileResult.success(new SimpleFileIO(oflags, File_maps, pathname));
        }
        if (APK_ROOT_PATH.equals(pathname)) {
            return FileResult.success(new SimpleFileIO(oflags, File_APK, pathname));
        }
        return null;
    }
}
