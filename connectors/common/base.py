from abc import ABC, abstractmethod
import httpx
class Connector(ABC):
    def __init__(self, base_url='', token='', timeout=10):
        self.base_url=base_url; self.token=token; self.timeout=timeout
    def client(self):
        return httpx.Client(timeout=self.timeout, headers={"Authorization":"Bearer ***redacted***"})
    @abstractmethod
    def collect(self): ...
