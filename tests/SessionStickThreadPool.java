package org.easier.multiplexer;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.easier.multiplexer.net.SocketConnection;
import org.easier.multiplexer.task.ClientTask;
import org.easier.util.ETopGlobals;
import org.easier.util.Log;
/**
 * 
 * 通过使用单线程的ThreadPool对线程的生命周期和task进行管理，提供Thread资源的回收利用，断线重连机制。
 */
public class SessionStickThreadPool implements Executor{
    
    /**
     * CM 与 Etop 的连接数
     */
    private int connections;

    private ConnectionWorkerThreadPool[] pool;

    protected String managerName;

    public SessionStickThreadPool() {
        managerName = ConnectionManager.getInstance().getName();
    }

    void shutdown(boolean now) {

        // 关闭所有客户端连接
        ClientSession.closeAll();
        if (null == pool) {
        } else {
            for (ConnectionWorkerThreadPool thread : pool) {
                if (now) {
                    thread.shutdown();
                } else {
                    thread.shutdownNow();
                }
            }

        }
    }
    
    
    /**
     * Map that holds the list of connections to the server.
     * Key: thread name, Value: ConnectionWorkerThread.
     */
    private Map<String, ConnectionWorkerThread> serverConnections =
            new ConcurrentHashMap<String, ConnectionWorkerThread>(0);

    public Map<String, ConnectionWorkerThread> getServerConnections() {
        return serverConnections;
    }
    
    public void restart(){
        createThreadPool();
    }
    
    void start() {
        
        connections = ETopGlobals.getIntProperty("xmpp.manager.connections", 5);
        // Create empty thread pool
        createThreadPool();
        // Start thread that will send heartbeats to the server every 30 seconds
        // to keep connections to the server open.
        Thread hearbeatThread = new Thread() {
            public void run() {
                while (true) {
                    try {
                        Thread.sleep(30000);
                        for (ConnectionWorkerThread thread : serverConnections.values()) {
                            thread.getConnection().deliverRawText(" ");
                        }
                    } catch (InterruptedException e) {
                        // Do nothing
                    } catch (Exception e) {
                        Log.error(e);
                    }
                }
            }
        };
        hearbeatThread.setDaemon(true);
        hearbeatThread.setPriority(Thread.NORM_PRIORITY);
        hearbeatThread.start();
    }

    /**
     * ·无法提供服务则拒绝服务 ThreadPoolExecutor that verifies connection status before executing a task. If the connection is
     * invalid then the worker thread will be dismissed and the task will be injected into the pool again.
     */
    private class ConnectionWorkerThreadPool extends ThreadPoolExecutor {
        private final String name;
        public ConnectionWorkerThreadPool(String name) {
            super(1, 1, 60, TimeUnit.SECONDS, new LinkedBlockingQueue<Runnable>(), 
                    new ConnectionsWorkerFactory(name),
                    new ThreadPoolExecutor.AbortPolicy());
            this.name = name;
        }
        /*public String getName(){
            return this.name;
        }*/
        protected void beforeExecute(Thread thread, Runnable task) {
            super.beforeExecute(thread, task);
            ConnectionWorkerThread workerThread = (ConnectionWorkerThread) thread;
            // Check that the worker thread is valid. This means that it has a valid connection
            // to the server
            if (!workerThread.isValid()) {
                // Request other thread to process the task. In fact, a new thread
                // will be created by the
                execute(task);
                // Throw an exception so that this worker is dismissed
                throw new IllegalStateException(
                        "There is no connection to the server or connection is lost.");
            }
        }

        public void shutdown() {
            // Notify the server that the connection manager is being shut down
            execute(new Runnable() {
                public void run() {
                    ConnectionWorkerThread thread = (ConnectionWorkerThread) Thread.currentThread();
                    thread.notifySystemShutdown();
                }
            });
            // Stop the workers and shutdown
            super.shutdown();
        }
        
        protected void terminated() {
            super.terminated();
            ConnectionWorkerThread thread = (ConnectionWorkerThread) Thread.currentThread();
            SocketConnection con = thread.getConnection();
            if(null != con){
                con.close();
            }
            Log.error("关闭连接-"+thread.getName());
            serverConnections.remove(Thread.currentThread().getName());
        }
    }

    @Override
    public void execute(Runnable command) {
        if (!(command instanceof ClientTask)) {
            throw new IllegalArgumentException();
        }
        ClientTask task = (ClientTask)command;
        ConnectionWorkerThreadPool executor = pool[Math.abs(task.getStreamID().hashCode())%connections];
        executor.execute(task);
    }
    
    /**
     * Creates a new thread pool that will not contain any thread. So new connections
     * won't be created to the server at this point.
     */
    private void createThreadPool() {
        if (null != pool) {
            for (int i = 0; i < pool.length; i++) {
                if (null != pool[i] && !pool[i].isShutdown()) {
                    pool[i].shutdown();
                }
            }
        }
        pool= new ConnectionWorkerThreadPool[connections];
        for(int i =0;i<pool.length;i++){
            pool[i] = new ConnectionWorkerThreadPool("ConnectionManager-"+i);
            pool[i].prestartCoreThread();
        }
    }
    
    
    /**
     * Factory of threads where is thread will create and keep its own connection
     * to the server. If creating new connections to the server failes 2 consecutive
     * times then existing client connections will be closed.
     */
    private class ConnectionsWorkerFactory implements ThreadFactory {
        final ThreadGroup group;
        final AtomicInteger threadNumber = new AtomicInteger(1);
        final AtomicInteger failedAttempts = new AtomicInteger(0);
        
        final String managerName;

        public ConnectionsWorkerFactory(String managerName) {
            SecurityManager s = System.getSecurityManager();
            group = (s != null) ? s.getThreadGroup() : Thread.currentThread().getThreadGroup();
            this.managerName = managerName;
        }

        public Thread newThread(Runnable r) {
            //拒绝执行任务
            ConnectionWorkerThread t = null;
            try{
             // Create new worker thread that will include a connection to the server
                t = new ConnectionWorkerThread(group, r, managerName + "-Connection Worker - "
                        + threadNumber.getAndIncrement(), 0);
                if (t.isDaemon())
                    t.setDaemon(false);
                if (t.getPriority() != Thread.NORM_PRIORITY)
                    t.setPriority(Thread.NORM_PRIORITY);
                // Return null if failed to create worker thread
                if (!t.isValid()) {
                    int attempts = failedAttempts.incrementAndGet();
                    if (attempts == 2 && serverConnections.size() == 0) {
                        // Server seems to be unavailable so close existing client connections
                        // Clean up the counter of failed attemps to create new connections
                        shutdown(true);
                        restart();
                        failedAttempts.set(0);
                        Thread.sleep(3000);
                    }
                    Log.error(String.format("%s-获取连接失败......消息包丢弃", t.getName()));
                    return null;
                } else {
                    // Clean up the counter of failed attemps to create new connections
                    failedAttempts.set(0);
                    // Update number of available connections to the server
                    serverConnections.put(t.getName(), t);
                    Log.error(String.format("%s--尝试获取连接成功...", t.getName()));
                    return t;
                }
            }catch(Exception ex){
                Log.error("获取连接失败。。。。未知错误",ex);
                return null;
            }
        }
    }

}
