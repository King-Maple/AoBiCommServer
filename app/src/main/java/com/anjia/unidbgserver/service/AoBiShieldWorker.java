package com.anjia.unidbgserver.service;

import com.alibaba.fastjson.JSONObject;
import com.anjia.unidbgserver.config.UnidbgProperties;
import com.github.unidbg.worker.Worker;
import com.github.unidbg.worker.WorkerPool;
import com.github.unidbg.worker.WorkerPoolFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service("AoBiShieldWorker")
public class AoBiShieldWorker extends Worker {

    private UnidbgProperties unidbgProperties;
    private WorkerPool pool;
    private AoBiShield AoBiShield;

    public AoBiShieldWorker(WorkerPool pool) {
        super(pool);
    }

    @Autowired
    public AoBiShieldWorker(UnidbgProperties unidbgProperties, @Value("${spring.task.execution.pool.core-size:4}") int poolSize) {
        super(null);
        this.unidbgProperties = unidbgProperties;
        if (this.unidbgProperties.isAsync()) {
            pool = WorkerPoolFactory.create((pool) -> new AoBiShieldWorker(unidbgProperties.isDynarmic(), unidbgProperties.isVerbose(),pool), Math.max(poolSize, 4));
            log.info("线程池为:{}", Math.max(poolSize, 4));
        } else {
            this.AoBiShield = new AoBiShield(unidbgProperties);
        }
    }

    public AoBiShieldWorker(boolean dynarmic, boolean verbose, WorkerPool pool) {
        super(pool);
        this.unidbgProperties = new UnidbgProperties();
        unidbgProperties.setDynarmic(dynarmic);
        unidbgProperties.setVerbose(verbose);
        log.info("是否启用动态引擎:{},是否打印详细信息:{}", dynarmic, verbose);
        this.AoBiShield = new AoBiShield(this.unidbgProperties);
    }

    @Async
    public CompletableFuture<String> AoBiShield(JSONObject jsonObject) {
        AoBiShieldWorker worker;
        String data;
        if (this.unidbgProperties.isAsync()) {
            while (true) {
                if ((worker = pool.borrow(2, TimeUnit.SECONDS)) == null) {
                    continue;
                }
                data = worker.doWork(jsonObject);
                pool.release(worker);
                break;
            }
        } else {
            synchronized (this) {
                data = this.doWork(jsonObject);
            }
        }
        return CompletableFuture.completedFuture(data);
    }

    @SneakyThrows
    @Override
    public void destroy() {
        this.AoBiShield.destroy();
        log.info("线程池为:{}", AoBiShield);
    }

    private String doWork(JSONObject jsonObject) {
        String val = jsonObject.getString("SafeComm");
        return AoBiShield.safeCommToServer(val);
    }

}
