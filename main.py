import sys
from orchestrators.api_orchestrator import APIManager
from orchestrators.graph_orchestrator import Graph_Manager

def run_sync(sync_nvd=True, sync_mitre=True, mode='lastmod', days=1, chunk_size=1000):
    """
    Orchestrates the synchronization of vulnerability and attack framework data.
    
    :param sync_nvd: Boolean to toggle NVD CVE synchronization.
    :param sync_mitre: Boolean to toggle MITRE ATT&CK synchronization.
    :param mode: 'full' for complete ingestion, 'lastmod' for incremental (NVD only).
    :param days: Lookback period for 'lastmod' mode (NVD only).
    """
    manager = APIManager()
    
    try:
        if sync_mitre:
            manager.run_mitre_sync()

        if sync_nvd:
            manager.run_nvd_sync(mode=mode, days=days, limit=None, chunk_limit=chunk_size)

        print("\n[!] Synchronization cycle finished.")

    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] Sync failed: {e}")
        sys.exit(1)


def run_visualization():
    gm = Graph_Manager()
    gm.make_graph(
        query_type='volume_over_time', 
        window_type='1m', 
        graph_type='line', 
        smooth=None
    )

if __name__ == "__main__":
    #run_sync(sync_nvd=True, sync_mitre=False, mode='lastmod', days=60, chunk_size=2000)
    #run_visualization()
    pass