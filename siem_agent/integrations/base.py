from abc import ABC, abstractmethod

class BaseSiemConnector(ABC):
    """
    Clase base para conectores SIEM. 
    Permite establecer un contrato para integraciones futuras que necesiten buscar activamente logs (pull) desde una API.
    """
    @abstractmethod
    def start(self):
        """Inicia el conector (ej. arranca un proceso de polling)"""
        pass
    
    @abstractmethod
    def stop(self):
        """Detiene el conector"""
        pass
