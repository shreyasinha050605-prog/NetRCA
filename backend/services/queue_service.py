import queue
import threading
from typing import Callable


class RCAQueueService:
    """
    Lightweight in-process worker queue for demo/MVP RCA orchestration.
    This keeps background analysis decoupled from HTTP request latency.
    """

    def __init__(self) -> None:
        self._queue: queue.Queue[int] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._worker: Callable[[int], None] | None = None
        self._started = False

    def start(self, worker: Callable[[int], None]) -> None:
        if self._started:
            return
        self._worker = worker
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._started = True

    def enqueue(self, incident_id: int) -> None:
        self._queue.put(incident_id)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                incident_id = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                if self._worker:
                    self._worker(incident_id)
            finally:
                self._queue.task_done()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)


rca_queue = RCAQueueService()
