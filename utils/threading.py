#!/usr/bin/env python3

import os
import time
import threading
import multiprocessing
import logging
from queue import Queue, Empty
from collections import deque

# Configure logger
logger = logging.getLogger('fronthunter.threading')


class RateLimiter:
    
    def __init__(self, requests_per_second=None, requests_per_minute=None, 
                 requests_per_hour=None, burst_size=None, distribute_evenly=True):

        self.rate_per_second = 0
        
        if requests_per_second is not None:
            self.rate_per_second = max(self.rate_per_second, requests_per_second)
        
        if requests_per_minute is not None:
            self.rate_per_second = max(self.rate_per_second, requests_per_minute / 60.0)
        
        if requests_per_hour is not None:
            self.rate_per_second = max(self.rate_per_second, requests_per_hour / 3600.0)
        
        if self.rate_per_second <= 0:
            raise ValueError("At least one non-zero rate limit must be provided")
        
        self.min_interval = 1.0 / self.rate_per_second
        
        self.burst_size = burst_size if burst_size is not None else max(1, int(self.rate_per_second))
        
        self.available_tokens = self.burst_size
        self.last_refill_time = time.time()
        
        self.distribute_evenly = distribute_evenly
        self.last_request_time = time.time()
        
        self.lock = threading.RLock()
        
        self.request_history = deque(maxlen=1000)
        
        logger.debug(f"Rate limiter initialized with {self.rate_per_second:.2f} req/sec, "
                   f"burst size: {self.burst_size}, even distribution: {distribute_evenly}")
    
    def _refill_tokens(self):
        """Refill the token bucket based on elapsed time since last refill."""
        now = time.time()
        elapsed = now - self.last_refill_time
        new_tokens = elapsed * self.rate_per_second
        
        self.available_tokens = min(self.burst_size, self.available_tokens + new_tokens)
        self.last_refill_time = now
    
    def _wait_for_even_distribution(self):
        """
        If even distribution is enabled, wait until enough time has passed
        since the last request to maintain the desired rate.
        """
        if not self.distribute_evenly:
            return
        
        now = time.time()
        elapsed = now - self.last_request_time
        
        # If we haven't waited long enough for even distribution, sleep
        if elapsed < self.min_interval:
            sleep_time = self.min_interval - elapsed
            logger.debug(f"Rate limiter: sleeping {sleep_time:.3f}s for even distribution")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def acquire(self, timeout=None):

        start_time = time.time()
        
        with self.lock:
            self._wait_for_even_distribution()
            
            self._refill_tokens()
            
            if self.available_tokens >= 1:
                self.available_tokens -= 1
                self.request_history.append(time.time())
                return True
            
            if timeout == 0:
                return False
            
            wait_time = (1 - self.available_tokens) / self.rate_per_second
            
            if timeout is not None and wait_time > timeout:
                return False
            
            
        logger.debug(f"Rate limiter: waiting {wait_time:.3f}s for token")
        time.sleep(wait_time)
        
        with self.lock:
            self._refill_tokens()
            
            if self.available_tokens >= 1:
                self.available_tokens -= 1
                self.request_history.append(time.time())
                return True
            
            if timeout is not None and (time.time() - start_time) >= timeout:
                return False
            
            logger.warning("Rate limiter: unexpected state, retrying acquisition")
            return self.acquire(timeout=timeout)
    
    def get_stats(self):
        """Get current rate limiter statistics."""
        with self.lock:
            now = time.time()
            self._refill_tokens()  # Update the token count
            
            recent_requests = list(self.request_history)
            requests_last_second = sum(1 for t in recent_requests if now - t <= 1.0)
            requests_last_minute = sum(1 for t in recent_requests if now - t <= 60.0)
            requests_last_hour = len(recent_requests)  # Limited by deque maxlen
            
            return {
                "available_tokens": self.available_tokens,
                "burst_size": self.burst_size,
                "rate_per_second": self.rate_per_second,
                "requests_last_second": requests_last_second,
                "requests_last_minute": requests_last_minute,
                "requests_last_hour": requests_last_hour,
                "request_history_size": len(recent_requests)
            }


class ThreadPoolWithRateLimiting:
    """
    Thread pool that uses a rate limiter to control the rate of task execution.
    Similar interface to ThreadPoolExecutor but with rate limiting capabilities.
    """
    
    def __init__(self, max_workers=None, rate_limiter=None):
        self.max_workers = max_workers or get_optimal_thread_count()
        self.rate_limiter = rate_limiter
        self.task_queue = Queue()
        self.workers = []
        self.results = {}
        self.shutdown_flag = threading.Event()
        self.lock = threading.RLock()
        self.task_count = 0
        
        # Start worker threads
        for _ in range(self.max_workers):
            worker = threading.Thread(target=self._worker_thread)
            worker.daemon = True
            worker.start()
            self.workers.append(worker)
        
        logger.debug(f"Thread pool initialized with {self.max_workers} workers and rate limiting")
    
    def _worker_thread(self):
        """Worker thread that processes tasks from the queue with rate limiting."""
        while not self.shutdown_flag.is_set():
            try:
                task_id, func, args, kwargs = self.task_queue.get(block=True, timeout=0.5)
                
                if self.rate_limiter:
                    if not self.rate_limiter.acquire(timeout=10.0):
                        logger.warning("Rate limiter timeout exceeded, retrying task")
                        self.task_queue.put((task_id, func, args, kwargs))
                        continue
                
                try:
                    result = func(*args, **kwargs)
                    with self.lock:
                        self.results[task_id] = (True, result)
                except Exception as e:
                    with self.lock:
                        self.results[task_id] = (False, e)
                finally:
                    self.task_queue.task_done()
                    
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Unexpected error in worker thread: {e}")
                continue
    
    def submit(self, func, *args, **kwargs):
        if self.shutdown_flag.is_set():
            raise RuntimeError("Cannot submit tasks after shutdown")
        
        with self.lock:
            task_id = self.task_count
            self.task_count += 1
        
        # Create a Future-like object to return
        future = _Future(task_id, self)
        
        # Add the task to the queue
        self.task_queue.put((task_id, func, args, kwargs))
        
        return future
    
    def shutdown(self, wait=True):
        if wait:
            # Wait for all tasks to be processed
            self.task_queue.join()
        
        # Set the shutdown flag to stop worker threads
        self.shutdown_flag.set()
        
        # Wait for all worker threads to exit if requested
        if wait:
            for worker in self.workers:
                worker.join()
        
        logger.debug("Thread pool shutdown complete")


class _Future:
    """Simple Future-like class to provide result access for ThreadPoolWithRateLimiting."""
    
    def __init__(self, task_id, pool):
        self.task_id = task_id
        self.pool = pool
        self._done = threading.Event()
    
    def done(self):
        """Check if the task is done."""
        with self.pool.lock:
            return self.task_id in self.pool.results
    
    def result(self, timeout=None):
        start_time = time.time()
        while not self.done():
            if timeout is not None and time.time() - start_time > timeout:
                raise TimeoutError("Timeout waiting for task result")
            time.sleep(0.05)  # Small sleep to avoid CPU spinning or something like that.
        
        with self.pool.lock:
            success, result = self.pool.results[self.task_id]
        
        if success:
            return result
        else:
            # If not successful, result is the exception
            raise result


def get_optimal_thread_count():
    # Get the number of CPU cores
    cpu_count = os.cpu_count() or 1
    
    # For I/O bound operations like network requests,
    # it's often beneficial to use more threads than CPU cores
    # since threads will spend most of their time waiting for network responses
    
    # A good rule of thumb is 2-4 times the number of cores
    # We'll use 2x here, but this can be adjusted based on testing
    optimal_count = cpu_count * 2
    
    # Set a reasonable upper limit to avoid creating too many threads
    # which could lead to resource contention
    max_threads = 50
    
    return min(optimal_count, max_threads)


def split_workload(items, num_workers):
    if not items:
        return []
    
    num_chunks = min(num_workers, len(items))
    
    chunk_size = len(items) // num_chunks
    remainder = len(items) % num_chunks
    
    chunks = []
    start = 0
    
    for i in range(num_chunks):
        end = start + chunk_size + (1 if i < remainder else 0)
        chunks.append(items[start:end])
        start = end
    
    return chunks 