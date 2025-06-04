import time
from ui import run_gui

def virus_tool_startup():
    green = "\033[92m"
    reset = "\033[0m"
    banner = fr"""
{green}
════════════════════════════════════                                            
          ____                            
        ,'  , `.    ,---,      ,----..    
     ,-+-,.' _ |  .'  .' `\   /   /   \   
  ,-+-. ;   , ||,---.'     \ |   :     :  
 ,--.'|'   |  ;||   |  .`\  |.   |  ;. /  
|   |  ,', |  '::   : |  '  |.   ; /--`   
|   | /  | |  |||   ' '  ;  :;   | ;  __  
'   | :  | :  |,'   | ;  .  ||   : |.' .' 
;   . |  ; |--' |   | :  |  '.   | '_.' : 
|   : |  | ,    '   : | /  ; '   ; : \  | 
|   : '  |/     |   | '` ,/  '   | '/  .' 
;   | |`-'      ;   :  .'    |   :    /   
|   ;/          |   ,.'       \   \ .'    
'---'           '---'          `---`      
 Malware Detection & Generator v1.0
════════════════════════════════════
{reset}
Starting up...
"""
    print(banner)
    print("Loading", end="", flush=True)
    for _ in range(6):
        time.sleep(0.4)
        print(".", end="", flush=True)
    print("\n")

if __name__ == "__main__":
    virus_tool_startup()
    run_gui()
