let EchoApp = angular.module('EchoApp', ['ngAnimate']);

EchoApp.controller("ParentCtrl", function($scope, $http) {
  // variable de conservation de l'état du backend
  $scope.health = {};

  // variable de sélection multiple de noeuds pour scan
  $scope.nodesSelected = [];

  $scope.nodesAllTypeSelected = [];

  // famille de type d'adressage : 
  $scope.address_family = {};

  // liste des interfaces
  $scope.interfaces = [];
  // interface sélectionné
  $scope.interface = undefined;
  $scope.interfaceData = undefined;

  // choix d'adresse IP quand nécessaire
  $scope.listInterfaceIP = [];

  // JSON d'IP à processer
  $scope.jsonIP = undefined;

  // adresse IP : 
  $scope.cible = "192.168.1.0/24";

  // liste de thème :
  $scope.themes = [
    'darkgreen',
    'whiteblue',
    'whitedebug',
  ];
  $scope.themeSelected = 'darkgreen';

  // visibilité du menu de configuration
  $scope.menuConf = false;
  // onglets du menu de configuration
  $scope.menuConfState = true;
  $scope.menuConfNetwork = false;
  $scope.menuConfTheme = false;

  $scope.sendToastData = function(titre, texte, className) {
    $scope.$broadcast('ToastMessage', {
      'titre' : titre,
      'texte' : texte,
      'className': className,
    })
  };

  // fonction de changement de thème : 
  $scope.changeTheme = function(themeName) {
    document.documentElement.setAttribute('data-theme', themeName);
    localStorage.setItem('theme', themeName);
    // on envoie au graph l'indication d'un rechargement de style nécessaire
    $scope.$broadcast('reloadStyle', {'theme' : themeName});
  };

  // fonction de récupération des familles d'adressage : 
  $scope.getAddressFamily = function() {
    let req = {
      method : 'GET',
      url : '/json/address_family',
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.address_family = response.data;
      },
      // si la requête échoue :
      function(error) {
        $scope.sendToastData('Interfaces', "Problème address family : " + error, "echo_toast_error");
        console.log(error);
      }
    );
  };

  // fonction de récupération des interfaces : 
  $scope.getInterfaces = function() {
    let req = {
      method : 'GET',
      url : '/json/interfaces',
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.sendToastData('Interfaces', "récupération list interfaces", "echo_toast_info");
        $scope.interfaces = response.data;
      },
      // si la requête échoue :
      function(error) {
        $scope.sendToastData('Interfaces', "Problème list interfaces : " + error, "echo_toast_error");
        console.log(error);
      }
    );
  };

  // fonction de récupération des info de l'interface courante : 
  $scope.getInterfaceData = function() {
    if($scope.interface == null) {
      return; // on évite de requêter une absence d'interface.
    };

    let req = {
      method : 'GET',
      url : '/json/interface/' + $scope.interface,
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.sendToastData('Echosounder', "Interface Info", "echo_toast_info");
        $scope.interfaceData = response.data;
        console.log($scope.interfaceData);
        // on place en IPv4 l'ip dans listInterfaceIP
        $scope.listInterfaceIP = response.data[$scope.address_family['IPv4']];
      },
      // si la requête échoue :
      function(error) {
        $scope.sendToastData('Echosounder', "API erreur : " + error, "echo_toast_error");
        console.log(error);
      }
    );
  };

  // fonction de traitement du JSON d'une interface en IP/CIDR
  $scope.jsonInterfaceToIPCIDR = function() {
    if($scope.jsonIP == undefined) { return }
    let data = JSON.parse($scope.jsonIP);
    let req = {
      method : 'POST',
      url : '/json/ipcidr',
      headers: {'Content-Type': 'application/json'},
      data: {'ip' : data.addr, "cidr" : data.netmask},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.cible = response.data.ipcidr;
        $scope.$apply();
      },
      // si la requête échoue :
      function(error) {
        $scope.sendToastData('Interface', "conversion IPCIDR : " + error, "echo_toast_error");
        console.log(error);
      }
    );
  };

  // fonction de vérification d'accessibilité du backend : 
  $scope.getHealth = function() {
    let req = {
      method : 'GET',
      url : '/json/health',
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.sendToastData('Echosounder', "API fonctionnelle", "echo_toast_info");
        $scope.health = response.data;
        //$scope.$apply();

        // on appelle l'ensemble des fonctionnalités de vérification de dependances
        $scope.getHealthNmap();
        $scope.getHealthModules();

        // on en profite pour récupérer les familles d'adresse : 
        $scope.getAddressFamily();
        // on en profite pour récupérer les interfaces : 
        $scope.getInterfaces();
      },
      // si la requête échoue :
      function(error) {
        $scope.sendToastData('Echosounder', "API erreur : " + error, "echo_toast_error");
        console.log(error);
      }
    );
  };

  // fonction de vérification d'accessibilité de nmap : 
  $scope.getHealthNmap = function() {
    let req = {
      method : 'GET',
      url : '/json/health/nmap',
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.health['nmap'] = response.data.nmap;
        //$scope.$apply();
      },
      // si la requête échoue :
      function(error) {
        $scope.sendToastData('Echosounder', "API erreur : " + error, "echo_toast_error");
        console.log(error);
      }
    );
  };

  // fonction de vérification d'accessibilité des modules python : 
  $scope.getHealthModules = function() {
    let req = {
      method : 'GET',
      url : '/json/health/dependencies',
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.health['dependencies'] = response.data.dependencies;
        //$scope.$apply();
      },
      // si la requête échoue :
      function(error) {
        $scope.sendToastData('Echosounder', "API erreur : " + error, "echo_toast_error");
        console.log(error);
      }
    );
  };

  // event d'effacement du menu de configuration : 
  $scope.$on('resetPanels', function() {
    $scope.menuConf = false;
    $scope.$apply();
  });

  $scope.getHealth();
  console.log($scope);
});

EchoApp.controller("leftPanelMenu", function($scope, $rootScope, $http) {
  $scope.showMenu1 = false;
  $scope.showMenu2 = false;
  $scope.showMenu3 = false;
  $scope.portShow = false;

  $scope.machineCible = "0.0.0.0"
  $scope.portStart = "0"
  $scope.portEnd = "400"

  $scope.sendBroadcastScan = function(typeParam, callScanParam) {
    if(typeParam == 'cidr') {
      $rootScope.$broadcast('request_scan', {'cible' : $scope.$parent.cible, 'callScan' : callScanParam});
    }else if (typeParam.startsWith('IP')) {
      if($scope.$parent.nodesSelected.length == 0) {
        $rootScope.$broadcast('request_scan', {'cible' : $scope.machineCible, 'callScan' : callScanParam});
      }else {
        $scope.$parent.nodesSelected.forEach(function(machinesCible) {
          $rootScope.$broadcast('request_scan', {'cible' : machinesCible, 'callScan' : callScanParam});
        });
      }
    }else if(typeParam == 'IP_ports'){
      if($scope.$parent.nodesSelected.length == 0) {
        $rootScope.$broadcast('request_scan', {'cible' : $scope.machineCible, 'port_start' : $scope.portStart, 'port_end' : $scope.portEnd, 'callScan' : callScanParam});
      }else {
        $scope.$parent.nodesSelected.forEach(function(machinesCible) {
          $rootScope.$broadcast('request_scan', {'cible' : machinesCible, 'port_start' : $scope.portStart, 'port_end' : $scope.portEnd, 'callScan' : callScanParam});
        });
      }
    }else if(typeParam == 'None'){
      $rootScope.$broadcast('request_scan', {'callScan' : callScanParam});
    }else {
      console.log("Erreur, type de scan non reconnu");
      console.log(typeParam);
      console.log(callScanParam);
    }
  };

  $scope.clickFastPing = function() {
    console.log("emit fast ping request");
    $scope.sendBroadcastScan('cidr', 'request_fast_ping');
  };

  $scope.clickScanARP = function() {
    console.log("emit arp scan request");
    $scope.sendBroadcastScan('cidr', 'request_arp_scan');
  };

  $scope.clickScanDHCP = function() {
    console.log("emit dhcp cidr scan request");
    $scope.sendBroadcastScan('cidr', 'request_dhcp_cidr_scan');
  };

  $scope.clickScanCIDRTraceroute = function() {
    console.log("emit trace cidr scan request");
    $scope.sendBroadcastScan('cidr', 'request_traceroute_cidr_scan');
  };

  $scope.clickTraceroute = function() {
    console.log("emit trace scan request");
    $scope.sendBroadcastScan('None', 'request_traceroute_scan');
  };

  $scope.clickTracerouteLocal = function() {
    console.log("emit trace local scan request");
    $scope.sendBroadcastScan('None', 'request_traceroute_local_scan');
  };

  $scope.clickScanProfiling = function() {
    console.log("emit profiling scan request");
    $scope.sendBroadcastScan('IP', 'request_profiling_scan');
  };

  $scope.clickScanServices = function() {
    if ($scope.portShow){
      console.log("emit services scan request");
      $scope.sendBroadcastScan('IP_ports', 'request_services_scan');
    }else{
      $scope.portShow = true;
    }
  };

  $scope.clickScanFastServices = function() {
    console.log("emit services fast scan request");
    $scope.sendBroadcastScan('IP', 'request_services_fast_scan');
  };

  $scope.clickScanReversePTR = function() {
    console.log("emit reverse PTR scan request");
    $scope.sendBroadcastScan('IP', 'request_reverse_ptr_scan');
  };

  $scope.clickScanSSHFingerprint = function() {
    console.log("emit fingerprint SSH scan request");
    $scope.sendBroadcastScan('IP', 'request_fingerprint_ssh_scan');
    $rootScope.$broadcast('request_scan', {'cible' : $scope.machineCible, 'callScan' : 'request_fingerprint_ssh_scan'});
  };

  $scope.clickScanSMB = function() {
    console.log("emit SMB scan request");
    $scope.sendBroadcastScan('IP', 'request_smb_scan');
  };

  $scope.clickScanSNMP = function() {
    console.log("emit SNMP scan request");
    $scope.sendBroadcastScan('IP', 'request_snmp_scan');
  };

  $scope.clickScanSNMPnetstat = function() {
    console.log("emit SNMP scan request");
    $scope.sendBroadcastScan('IP', 'request_snmp_netstat_scan');
  };

  $scope.clickScanSNMPprocess = function() {
    console.log("emit SNMP scan request");
    $scope.sendBroadcastScan('IP', 'request_snmp_process_scan');
  };

  $scope.clickScanNTP = function() {
    console.log("emit NTP scan request");
    $scope.sendBroadcastScan('IP', 'request_ntp_scan');
  };
  
  $scope.clickScanRDP = function() {
    console.log("emit RDP scan request");
    $scope.sendBroadcastScan('IP', 'request_rdp_scan');
  };

  $scope.clickScanTracerouteCible = function() {
    console.log("emit traceroutecible scan request");
    $scope.sendBroadcastScan('IP', 'request_trace_cible_scan');
  };

  $scope.clickResolveAS = function() {
    console.log("emit resolve AS scan request");
    $scope.sendBroadcastScan('None', 'request_resolve_as_scan');
  };

  $scope.getSelectionScan = function() {
    console.log("emit get selection request");
    $scope.sendBroadcastScan('None', 'request_selection_scan');
  };

  $scope.deleteIPSelected = function(ip) {
    let index = $scope.$parent.nodesSelected.indexOf(ip);
    if(index != -1) {
      $scope.$parent.nodesSelected.splice(index, 1);
    }
  };

  $scope.deleteAllIPSelected = function() {
    $scope.$parent.nodesSelected = [];
  };

  $scope.$on('updatePanelNodeData',function(event, nodedata, nodetype) {
    if(nodetype == 'IP') { // on prend que les IP
      $scope.machineCible = nodedata.data_ip;
      $scope.$apply();
    }else if (nodetype == 'VLAN') {
      $scope.$parent.cible = nodedata.id;
      $scope.$apply();
    }
  });

  // event d'effacement des menu de gauche : 
  $scope.$on('resetPanels', function() {
    $scope.showMenu1 = false;
    $scope.showMenu2 = false;
    $scope.showMenu3 = false;
    $scope.$apply();
  });

  // debug de sélection de noeuds
  /*
  $scope.$parent.$watch('nodesSelected', function(test) {
    console.log(test);
  });
  */
});

EchoApp.controller("rightPanelMenu", function($scope, $rootScope, $http) {
  $scope.showMenu1 = false;
  $scope.showMenu2 = false;
  $scope.showMenu3 = false;

  $scope.showDialogNote = false;
  $scope.titreNote = "";
  $scope.texteNote = "";

  $scope.nodedata = undefined;
  $scope.servicedata = undefined;


  $scope.$on('updatePanelNodeData', function(event, node, typenode) {
    console.log(node);
    if(typenode == 'IP') { // on déclenche l'affichage du menu 1 avec les données du node
      $scope.nodedata = node.data;
      $scope.showMenu1 = true;
      $scope.showMenu2 = false;
      $scope.showMenu3 = false;
    }else if(typenode == 'Service') {
      $scope.servicedata = node.data;
      $scope.showMenu1 = false;
      $scope.showMenu2 = true;
      $scope.showMenu3 = false;
    }else {
      // on fais rien si on reconnais pas le type de noeud
    }
    // on demande à angularJS d'actualiser sa vue
    $scope.$apply();
  });

  $scope.checkAPI = function() {
    $scope.$parent.getHealth();
  };

  $scope.addNote = function() {
    $scope.showDialogNote = !$scope.showDialogNote;
  };

  $scope.getSelectionNote = function() {
    console.log("emit get selection request");
    $rootScope.$broadcast('request_scan', {'callScan' : 'request_selection_note'});
  };

  $scope.deleteNodesSelected = function(label) {
    let index = $scope.$parent.nodesAllTypeSelected.indexOf(label);
    if(index != -1) {
      $scope.$parent.nodesAllTypeSelected.splice(index, 1);
    }
  };

  $scope.deleteAllNodesSelected = function() {
    $scope.$parent.nodesAllTypeSelected = [];
  };

  $scope.addNoteValidate = function() {
    console.log("emit add note request");
    $rootScope.$broadcast('request_scan', {"cible" : $scope.$parent.nodesAllTypeSelected, 
                                            "titre" : $scope.titreNote,
                                            "texte" : $scope.texteNote, 
                                            'callScan' : 'request_add_note'});
    // on reset le dialog
    $scope.titreNote = "";
    $scope.texteNote = "";

  };

  $scope.exportPNG = function() {
    $rootScope.$broadcast('request_export_png', {});
  };

  $scope.exportJPG = function() {
    $rootScope.$broadcast('request_export_jpg', {});
  };

  $scope.exportJSON = function() {
    $rootScope.$broadcast('request_export_json', {});
  };

  $scope.importJSON = function() {
    if(document.getElementById('echo_json_upload').files.length == 0) {
      document.getElementById('echo_json_upload').click();
    }else {
      let f = document.getElementById('echo_json_upload').files[0],
          r = new FileReader();

      r.onloadend = function(e) {
        let data = e.target.result;
        // On envoie le fichier
        $rootScope.$broadcast('request_import_json', {'file' : data});
      }

      r.readAsBinaryString(f);
      document.getElementById('echo_json_upload').value = "";
    }
  };

  $scope.actualiseGraph = function() {
    // on fait une demande d'actualisation du graph : 
    $rootScope.$broadcast('request_actualise_graph', {});
  };

  $scope.deleteSelection = function() {
    $rootScope.$broadcast('request_delete_selection', {});
  };

  // event d'effacement des menu de droite : 
  $scope.$on('resetPanels', function() {
    $scope.showMenu1 = false;
    $scope.showMenu2 = false;
    $scope.showMenu3 = false;
    $scope.$apply();
  });

  $scope.$parent.$watch('nodesAllTypeSelected', function(test) {
    console.log(test);
  });
});

EchoApp.controller("notificationPanelMenu", function($scope, $timeout, $rootScope) {
  $scope.listToast = [];

  $scope.$on('ToastMessage', function(evt, toastData) {
    // fonction ajoutant un toast lors qu'elle reçoit les informations d'une notification
    // attends en entrée un objet de type : 
    // {
    //   'titre' : "un titre",
    //   'texte' : 'texte explicatif'
    // }
    $scope.listToast.push({
      'titre' : toastData.titre, 
      'texte' : toastData.texte,
      'className' : toastData.className,
    });
  });

  // fonction de trigger de watch tant que $scope.listToast n'est pas vide
  $scope.$watchCollection('listToast', function(newListToard, oldListToad) {
    if(newListToard.length == 0) {
      // on ne fait rien
    }else {
      // place un delay de 3 secondes plus on efface le premier élément de la liste
      $timeout(function() { $scope.listToast = $scope.listToast.slice(1);}, 7000);
    }
  })
});

EchoApp.controller("graphNetwork", function($scope, $document, $http) {
  // contexte couleurs
  $scope.rootColor = getComputedStyle(document.documentElement);
  console.log($scope.rootColor);

  // fonctions de récupérations de donnée Fast Scan
  $scope.getFastScan = function(cible) {
    $scope.$parent.sendToastData('FastPing', "lancement d'un scan", 'echo_toast_scan');
    let req = {
      method : 'POST',
      url : '/json/fast_scan',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };
    
    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('FastPing', "réception d'un scan", 'echo_toast_scan');
        console.log(response.data);
        // on appel la fonction de création de graphs :
        $scope.createCytoVlanGraph(response.data);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('FastPing', "erreur : " + error, 'echo_toast_error');
        console.log(error);
      }
    );
  };

  // fonctions de récupération de donnée scan ARP
  $scope.getARPScan = function(cible) {
    $scope.$parent.sendToastData('ARP Scan', "lancement d'un scan", 'echo_toast_scan');
    let req = {
      method : 'POST',
      url : '/json/arp_scan',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('ARP Scan', "réception d'un scan", 'echo_toast_scan');
        console.log(response.data);
        // on appel la fonction de création de graphs :
        $scope.createCytoVlanGraph(response.data);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('ARP Scan', "erreur Scan : " + error, 'echo_toast_error');
        console.log(error);
      }
    );
  };

  // fonction d'obtention d'IP du réseau local (ou opérateur) via traceroute CIDR
  $scope.getTracerouteCIDRScan = function(cible) {
    $scope.$parent.sendToastData('Traceroute CIDR Scan', "lancement d'un scan", 'echo_toast_scan');
    let req = {
      method : 'POST',
      url : '/json/trace_cidr_scan',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('Traceroute CIDR Scan', "réception d'un scan", 'echo_toast_scan');
        console.log(response.data);
        // on appel la fonction de création de graphs :
        $scope.createCytoTraceCIDRGraph(response.data);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('Traceroute CIDR Scan', "erreur Scan : " + error, 'echo_toast_error');
        console.log(error);
      }
    );
  };

  // fonction d'obtention d'IP du réseau local via DHCP scan sur CIDR
  $scope.getDHCP_CIDRScan = function(cible) {
    $scope.$parent.sendToastData('DHCP CIDR Scan', "lancement d'un scan", 'echo_toast_scan');
    let req = {
      method : 'POST',
      url : '/json/dhcp_cidr_scan',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('DHCP CIDR Scan', "réception d'un scan", 'echo_toast_scan');
        console.log(response.data);
        // on appel la fonction de création de graphs :
        $scope.createCytoCIDRGraph(response.data, cible);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('DHCP CIDR Scan', "erreur Scan : " + error, 'echo_toast_error');
        console.log(error);
      }
    );
  };

  // fonction d'obtention d'IP du réseau local (ou opérateur) via traceroute
  $scope.getTracerouteScan = function() {
    $scope.$parent.sendToastData('Traceroute Scan', "lancement d'un scan", 'echo_toast_scan');
    let list_root_server_ip =  [
      "198.41.0.4",
      "199.9.14.201",
      "192.33.4.12",
      "199.7.91.13",
      "192.203.230.10",
      "192.5.5.241",
      "192.112.36.4",
      "198.97.190.53",
      "192.36.148.17",
      "192.58.128.30",
      "193.0.14.129",
      "199.7.83.42",
      "202.12.27.33",
    ];
    list_root_server_ip.forEach(function(cible, index) {
      let interval = 5000; // 5 secondes entre chaque scan
      setTimeout(function () {
        let req = {
          method : 'POST',
          url : '/json/trace_scan',
          headers: {'Content-Type': 'application/json'},
          data : {'cible' : cible},
        };

        $http(req).then(
          // si la requête passe :
          
          function(response) {
            $scope.$parent.sendToastData('Traceroute Scan', "réception d'un scan", 'echo_toast_scan');
            console.log(response.data);
            // on appel la fonction de création de graphs :
            $scope.createCytoTraceGraph(response.data);
          },
          // si la requête échoue :
          function(error) {
            $scope.$parent.sendToastData('Traceroute Scan', "erreur Scan : " + error, 'echo_toast_error');
            console.log(error);
          }
        );
      }, index * interval);
    });
  };

  // fonction d'obtention d'IP des réseaux locaux (ou opérateurs) via traceroute
  $scope.getTracerouteLocalScan = function() {
    $scope.$parent.sendToastData('Traceroute Local Scan', "lancement d'un scan", 'echo_toast_scan');
    let list_local_cidr = [
        "0.0.0.0/8", 
        "100.64.0.0/10",
        "127.0.0.0/8", 
        "169.254.0.0/16", 
        "192.0.0.0/24", 
        "192.0.2.0/24", 
        "192.88.99.0/24",
        "192.175.48.0/24",
        "198.18.0.0/15", 
        "198.51.100.0/24", 
        "203.0.113.0/24",
        "224.0.0.0/4", 
        "233.252.0.0/24",
        "240.0.0.0/4", 
        "255.255.255.255/32",
    ];
    list_local_cidr.forEach(function(cidr, index) {
      let interval = 5000; // 5 secondes entre chaque scan
      setTimeout(function () {
        let req = {
          method : 'POST',
          url : '/json/trace_cidr_scan',
          headers: {'Content-Type': 'application/json'},
          data : {'cible' : cidr},
        }

        $http(req).then(
          // si la requête passe :
          
          function(response) {
            $scope.$parent.sendToastData('Traceroute Local Scan', "réception d'un scan", 'echo_toast_scan');
            console.log(response.data);
            // on appel la fonction de création de graphs :
            $scope.createCytoTraceCIDRGraph(response.data);
          },
          // si la requête échoue :
          function(error) {
            $scope.$parent.sendToastData('Traceroute Local Scan', "erreur Scan : " + error, 'echo_toast_error');
            console.log(error);
          }
        );
      }, index * interval);
    });
  };

  // fonctions de profiling machine (OS, device, ...)
  $scope.getProfilingScan = function(cible) {
    $scope.$parent.sendToastData('Profiling', "lancement d'un scan", 'echo_toast_scan');
    let req = {
      method : 'POST',
      url : '/json/profiling_scan',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('Profiling Scan', "réception d'un scan", 'echo_toast_scan');
        console.log(response.data);
        // on met à jour le node concerné via une fonction de sélection de node
        $scope.updateNodebyIP(cible, 'profiling', response.data['scan']);
        $scope.updateNodeOS(cible, response.data['scan']);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('Profiling Scan', "erreur Scan : " + error, 'echo_toast_error');
        console.log(error);
      }
    );
  };

  // fonctions de listage des services machine (par port)
  $scope.getServicesScan = function(cible, pstart, pend) {
    $scope.$parent.sendToastData('Services', "lancement d'un scan", 'echo_toast_scan');
    let req = {
      method : 'POST',
      url : '/json/services_scan',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible, 'port_start' : pstart, 'port_end' : pend},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('Services Scan', "réception d'un scan", 'echo_toast_scan');
        console.log(response.data);
        // on met à jour le graph en ajoutant des noeuds type service lié à la cible
        $scope.createCytoServiceGraph(response.data['scan']);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('Services Scan', "erreur Scan : " + error, 'echo_toast_error');
        console.log(error);
      }
    );
  };

  // fonctions de listage des services machine (par port)
  $scope.getServicesFastScan = function(cible) {
    $scope.$parent.sendToastData('Services', "lancement d'un fast scan", 'echo_toast_scan');
    let req = {
      method : 'POST',
      url : '/json/services_fast_scan',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('Services Fast Scan', "réception d'un scan", 'echo_toast_scan');
        console.log(response.data);
        // on met à jour le graph en ajoutant des noeuds type service lié à la cible
        $scope.createCytoServiceGraph(response.data['scan']);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('Services Fast Scan', "erreur Scan : " + error, 'echo_toast_error');
        console.log(error);
      }
    );
  };

  // fonction d'obtention du hostname par requête DNS reverse PTR sur cible
  $scope.getReversePTRScan = function(cible) {
    $scope.$parent.sendToastData('Reverse PTR', "lancement d'un scan", 'echo_toast_scan');
    let req = {
      method : 'POST',
      url : '/json/reverse_ptr_scan',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('Reverse PTR Scan', "réception d'un scan", 'echo_toast_scan');
        console.log(response.data);
        // on met à jour le node concerné via une fonction de sélection de node
        $scope.updateNodebyIP(cible, 'hostname PTR', response.data['scan']);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('Reverse PTR Scan', "erreur Scan : " + error, 'echo_toast_error');
        console.log(error);
      }
    );
  };

  // fonction d'obtention de fingerprint SSH par requête SSH sur cible
  $scope.getFingerprintSSHScan = function(cible) {
    $scope.$parent.sendToastData('Fingerprint SSH', "lancement d'un scan", 'echo_toast_scan');
    let req = {
      method : 'POST',
      url : '/json/fingerpting_ssh_scan',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('Fingerprint SSH Scan', "réception d'un scan", 'echo_toast_scan');
        console.log(response.data);
        // on met à jour le node concerné via une fonction de sélection de node
        $scope.updateNodebyIP(cible, 'fingerprint ssh', response.data['scan']);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('Fingerprint SSH Scan', "erreur Scan : " + error, 'echo_toast_error');
        console.log(error);
      }
    );
  };

  $scope.getSMBScan = function(cible) {
    $scope.$parent.sendToastData('SMB', "lancement d'un scan", 'echo_toast_scan');
    let req = {
      method : 'POST',
      url : '/json/scan_info_smb',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('SMB Scan', "réception d'un scan", 'echo_toast_scan');
        console.log(response.data);
        // on met à jour le node concerné via une fonction de sélection de node
        $scope.updateNodebyIP(cible, 'smb', response.data['scan']);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('SMB Scan', "erreur Scan : " + error, 'echo_toast_error');
        console.log(error);
      }
    );
  }

  $scope.getSNMPScan = function(cible) {
    $scope.$parent.sendToastData('SNMP info', "lancement d'un scan", 'echo_toast_scan');
    let req = {
      method : 'POST',
      url : '/json/scan_snmp_info',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('SNMP Scan', "réception d'un scan", 'echo_toast_scan');
        console.log(response.data);
        // on met à jour le node concerné via une fonction de sélection de node
        $scope.updateNodebyIP(cible, 'snmp_info', response.data['scan']);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('SNMP Scan', "erreur Scan : " + error, 'echo_toast_error');
        console.log(error);
      }
    );
  }

  $scope.getSNMPnetstatScan = function(cible) {
    $scope.$parent.sendToastData('SNMP netstat', "lancement d'un scan", 'echo_toast_scan');
    let req = {
      method : 'POST',
      url : '/json/scan_snmp_netstat',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('SNMP netstat', "réception d'un scan", 'echo_toast_scan');
        console.log(response.data);
        // on met à jour le node concerné via une fonction de sélection de node
        $scope.updateNodebyIP(cible, 'snmp_nestat', response.data['scan']);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('SNMP netstat', "erreur Scan : " + error, 'echo_toast_error');
        console.log(error);
      }
    );
  };

  $scope.getSNMPprocessScan = function(cible) {
    $scope.$parent.sendToastData('SNMP process', "lancement d'un scan", 'echo_toast_scan');
    let req = {
      method : 'POST',
      url : '/json/scan_snmp_processes',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('SNMP process', "réception d'un scan", 'echo_toast_scan');
        console.log(response.data);
        // on met à jour le node concerné via une fonction de sélection de node
        $scope.updateNodebyIP(cible, 'snmp_process', response.data['scan']);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('SNMP process', "erreur Scan : " + error, 'echo_toast_error');
        console.log(error);
      }
    );
  };

  $scope.getNTPScan = function(cible) {
    $scope.$parent.sendToastData('NTP', "lancement d'un scan", 'echo_toast_scan');
    let req = {
      method : 'POST',
      url : '/json/scan_ntp',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('NTP', "réception d'un scan", 'echo_toast_scan');
        console.log(response.data);
        // on met à jour le node concerné via une fonction de sélection de node
        $scope.updateNodebyIP(cible, 'ntp', response.data['scan']);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('NTP', "erreur Scan : " + error, 'echo_toast_error');
        console.log(error);
      }
    );
  };

  $scope.getRDPScan = function(cible) {
    $scope.$parent.sendToastData('RDP', "lancement d'un scan", 'echo_toast_scan');
    let req = {
      method : 'POST',
      url : '/json/scan_rdp_info',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('RDP Scan', "réception d'un scan", 'echo_toast_scan');
        console.log(response.data);
        // on met à jour le node concerné via une fonction de sélection de node
        $scope.updateNodebyIP(cible, 'rdp_info', response.data['scan']);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('RDP Scan', "erreur Scan : " + error, 'echo_toast_error');
        console.log(error);
      }
    );
  };

  $scope.getTraceCibleScan = function(cible) {
    $scope.$parent.sendToastData('trace cible', "lancement d'un scan", 'echo_toast_scan');
    let req = {
      method : 'POST',
      url : '/json/trace_scan',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('TraceCible Scan', "réception d'un scan", 'echo_toast_scan');
        console.log(response.data);
        // on met à jour le node concerné via une fonction de sélection de node
        $scope.createCytoTraceGraph(response.data);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('TraceCible Scan', "erreur Scan : " + error, 'echo_toast_error');
        console.log(error);
      }
    );
  };

  $scope.getResolveAS = function() {
    $scope.cyto.elements('node[type = "AS"]').forEach(function(node) {
      if(node.data('as_resolution')){
        return; // si la résolution à déjà été faite, on s'épargne de la refaire
      }
      // si il s'agit d'un multi-origin AS set, on fait deux requêtes, sinon une seule
      if(node.data('label').includes('_')){
        let list_asn = node.data('label').split('_');
        // on crée deux requêtes
        let req1 = {
          method : 'GET',
          url : 'https://rdap.arin.net/registry/autnum/' + list_asn[0],
          headers: {'Content-Type': 'application/rdap+json'},
        };
        let req2 = {
          method : 'GET',
          url : 'https://rdap.arin.net/registry/autnum/' + list_asn[1],
          headers: {'Content-Type': 'application/rdap+json'},
        };

        // on récupère les info d'AS
        $http(req1).then(
          // si la requête passe :
          function(response) {
            $scope.$parent.sendToastData('AS Resolution', "Récupération de donnée RDAP", 'echo_toast_scan');
            console.log(response.data);
            // on les fout dans le label du noeud
            if(node.data('label').includes(' ')) {
              node.data('label', node.data('label') + " & " + response.data.name);
            } else{
              node.data('label', node.data('label') + " " + response.data.name);
            }
            // on spécifie que la résolution a été effectué
            node.data('as_resolution', true);
          },
          // si la requête échoue :
          function(error) {
            $scope.$parent.sendToastData('AS Resolution', "erreur : " + error, 'echo_toast_error');
            console.log(error);
          }
        );

        // on récupère les info d'AS
        $http(req2).then(
          // si la requête passe :
          function(response) {
            $scope.$parent.sendToastData('AS Resolution', "Récupération de donnée RDAP", 'echo_toast_scan');
            console.log(response.data);
            // on les fout dans le label du noeud
            if(node.data('label').includes(' ')) {
              node.data('label', node.data('label') + " & " + response.data.name);
            } else{
              node.data('label', node.data('label') + " " + response.data.name);
            }
            // on spécifie que la résolution a été effectué
            node.data('as_resolution', true);
          },
          // si la requête échoue :
          function(error) {
            $scope.$parent.sendToastData('AS Resolution', "erreur : " + error, 'echo_toast_error');
            console.log(error);
          }
        );
      }else {
        // on crée une requête
        let req = {
          method : 'GET',
          url : 'https://rdap.arin.net/registry/autnum/' + node.data('label'),
          headers: {'Content-Type': 'application/rdap+json'},
        };
        // on récupère les info d'AS
        $http(req).then(
          // si la requête passe :
          function(response) {
            $scope.$parent.sendToastData('AS Resolution', "Récupération de donnée RDAP", 'echo_toast_scan');
            console.log(response.data);
            // on les fout dans le label du noeud
            node.data('label', node.data('label') + " " + response.data.name);
            // on spécifie que la résolution a été effectué
            node.data('as_resolution', true);
          },
          // si la requête échoue :
          function(error) {
            $scope.$parent.sendToastData('AS Resolution', "erreur : " + error, 'echo_toast_error');
            console.log(error);
          }
        );
      }
    });
  };

  // fonction de récupération des IP à scanner pour le panel de scan d'ip.
  $scope.getSelectionScan = function() {
    let list_ip = [];
    $scope.cyto.elements('node[type="IP"]:selected').forEach(function(node) {
      list_ip.push(node.data('data_ip'));
    });
    $scope.$parent.nodesSelected = list_ip;
  };

  // fonction de récupération de noeud pour y adjoindre une note.
  $scope.getSelectionNote = function() {
    
    let list_node = [];
    $scope.cyto.elements('node:selected').forEach(function(node) {
      list_node.push(node.data('id'));
    });
    $scope.$parent.nodesAllTypeSelected = list_node;
  };

  // ajout d'un noeud de type note au graph 
  $scope.addNote = function(targets, titre, texte) {
    let node = [];
    let edges = [];
    // on ajoute le noeud de commentaire
    node.push(
      {
        group:'nodes',
        data: {
          id : titre,
          label : texte,
          data: texte,
          type : 'note',
        },
      }
    );

    // on ajoute les liens vers les targets
    targets.forEach(function(target) {
      edges.push({
        group:'edges',
        data : {
          id : ('link ' + target + " " + titre + " "),
          source : titre,
          target : target,
          type : 'notelink',
        }
      });
    });
    
    // on ajoute l'ensemble des ip au graph
    $scope.cyto.add(node);
    // on ajoute l'ensemble des lien au graph
    $scope.cyto.add(edges);
    // on actualise la vue
    $scope.layout = $scope.cyto.layout($scope.options);
    $scope.layout.run();
  };

  // association requête vers nom de fonction
  $scope.listScanFunc = {
    'request_fast_ping' : $scope.getFastScan,
    'request_arp_scan' : $scope.getARPScan ,
    'request_traceroute_cidr_scan' : $scope.getTracerouteCIDRScan ,
    'request_dhcp_cidr_scan' : $scope.getDHCP_CIDRScan,
    'request_traceroute_scan' : $scope.getTracerouteScan ,
    'request_traceroute_local_scan' : $scope.getTracerouteLocalScan ,
    'request_profiling_scan' : $scope.getProfilingScan ,
    'request_services_scan' : $scope.getServicesScan ,
    'request_services_fast_scan' : $scope.getServicesFastScan ,
    'request_reverse_ptr_scan' : $scope.getReversePTRScan ,
    'request_fingerprint_ssh_scan' : $scope.getFingerprintSSHScan ,
    'request_smb_scan' : $scope.getSMBScan ,
    'request_snmp_scan' : $scope.getSNMPScan ,
    'request_snmp_netstat_scan' : $scope.getSNMPnetstatScan ,
    'request_snmp_process_scan' : $scope.getSNMPprocessScan ,
    'request_ntp_scan' : $scope.getNTPScan ,
    'request_rdp_scan' : $scope.getRDPScan,
    'request_trace_cible_scan' : $scope.getTraceCibleScan,
    'request_resolve_as_scan': $scope.getResolveAS,
    'request_selection_scan': $scope.getSelectionScan,
    'request_selection_note' : $scope.getSelectionNote,
    'request_add_note' : $scope.addNote,
  }

  // partie gestion du graph
  $scope.cyto = cytoscape({
		container: document.getElementById('mynetwork')
	});

  $scope.options = {
		name: 'fcose', // cose est quand même pas mal...
		fit: true,  // Whether to fit the network view after when done
		padding: 30,
		animate: true, // TODO : l'animation est constante, mais la force n'est pas recalculé, trouvé un moyen pour que ça soit le cas
		animationDuration: 1000,
		animationEasing: 'ease-out',
		//infinite: 'end', // OW SHI__
		nodeDimensionsIncludeLabels: true, // OUUUIIIIII
		randomize: true, // ça semble mettre les noeud dans leur ordre d'arrivée, ça me plait.
    packComponents: true,
	};

  $scope.loadStyle = function() {
    $scope.styles = [
      {
        selector: 'node',
        css: {
          'shape' : 'octagon',
          'color' : $scope.rootColor.getPropertyValue('--text2'),
          'background-color' : $scope.rootColor.getPropertyValue('--fond-noeuds'),
          'border-style' : 'none',
          'content': 'data(label)', // méga important, détermine quoi afficher comme donnée dans le label de noeud
          'text-outline-color': $scope.rootColor.getPropertyValue('--background-general'), 
          'text-outline-width' : 1,
          'text-valign': 'top',
          'text-halign': 'center',
          'opacity' : 1,
          'text-wrap': 'wrap',
          'background-fit' : 'contain',
          'font-family' : 'Hack',
          'z-index' : 10,
        },
      },
      {
        selector: 'node[type="note"]',
        css: {
          'shape' : 'round-rectangle',
          'text-valign': 'center',
          'text-halign': 'center',
          'text-wrap' : 'wrap',
          'font-size' : 8,
          'text-wrap': 'wrap',
          'text-max-width' : 260,
          'text-overflow-wrap' : 'whitespace',
          'text-justification' : 'auto',
          'width' : (node) => { return Math.min(260, node.data('label').length * 7) },
          'height' : (node) => { return (Math.floor(node.data('label').length/45) + 1) * 8 },
          'z-index' : 5,
        },
      },
      {
        selector: 'node[type="IP"]',
        css: {
          'background-image' : '/static/img/icone/ip_bg.png',
        },
      },
      {
        selector: 'node[type = "Service"]',
        css: {
          'width': '20px',
          'height': '20px',
          'background-image' : '/static/img/icone/service_bg.png',
        },
      },
      {
        selector: 'node[label*="gateway"]',
        css: {
          'background-image' : '/static/img/icone/gateway_bg.png',
        },
      },
      {
        selector: 'node[data.OS@="Windows"]',
        css: {
          'background-image' : '/static/img/icone/windows_bg.png',
        },
      },
      {
        selector: 'node[data.OS @*= "Linux"]',
        css: {
          'background-image' : '/static/img/icone/linux_bg.png',
        },
      },
      {
        selector: 'node[data.OS @= "Unknown"]',
        css: {
          'background-image' : '/static/img/icone/unknown_bg.png',
        },
      },
      {
        selector: 'node[data.OS @*= "Android"]',
        css: {
          'background-image' : '/static/img/icone/android_bg.png',
        },
      },
      {
        selector: 'node[data.OS @*= "Mac OS X"]',
        css: {
          'background-image' : '/static/img/icone/mac_bg.png',
        },
      },
      {
        selector: 'node[data.OS @*= "BSD"]',
        css: {
          'background-image' : '/static/img/icone/freebsd_bg.png',
        },
      },
      {
        selector: ':parent',
        css: {
          'text-valign': 'top',
          'text-halign': 'center', 
          'background-opacity': '0',
          'z-index' : -5,
        },
      },
      {
        selector: 'node:selected',
        css: {
          'border-width' : 2,
          'border-style' : 'solid',
          'border-color' : $scope.rootColor.getPropertyValue('--widget-background1'), 
          'ghost' : 'yes',
          "ghost-offset-y": 1,
          'ghost-opacity': 0.4,
        },
      },
      {
        selector: 'edge',
        css: {
          'line-color' : $scope.rootColor.getPropertyValue('--widget-background3'),
          'target-arrow-color' : $scope.rootColor.getPropertyValue('--widget-strong-contour1'), 
          'curve-style': 'bezier',
          'target-arrow-shape': 'triangle',
          'opacity' : 0.5,
        },
      },
    ];
    $scope.cyto.style($scope.styles);
  };
  $scope.loadStyle();

  // fonction de création du graph à partir d'un scan CIDR
  $scope.createCytoVlanGraph = function(scan_data) {
    let nodes = [];
    let edges = [];
    //ajout de la représentation du VLAN
    nodes.push(
      {
        group:'nodes',
        data: {
          id : scan_data.vlan,
          label : scan_data.vlan,
          type : 'VLAN',
        },
      }
    );

    // ajout du routeur gateway
    nodes.push(
      {
        group:'nodes',
        data: {
          id : (scan_data.local_data.gateway_ip + '\n' + scan_data.local_data.gateway_mac),
          label : ("gateway " + scan_data.local_data.gateway_ip + "\n" + scan_data.local_data.gateway_mac),
          type : 'IP',
          typeip: ipaddr.parse(scan_data.local_data.gateway_ip).range(),
          data : scan_data.local_data,
          data_ip : scan_data.local_data.gateway_ip,
          parent : scan_data.vlan,
        },
      }
    );

    // ajout des entités nmap :
    scan_data.scan.forEach(function(nodeAdd) {
      if(nodeAdd.IP != scan_data.local_data[2]) {
        nodes.push(
          {
            group:'nodes',
            data: {
              id : (nodeAdd.IP + '\n' + nodeAdd.mac),
              label : (nodeAdd.IP + '\n' + nodeAdd.mac),
              type : 'IP',
              typeip : ipaddr.parse(nodeAdd.IP).range(),
              data : nodeAdd,
              data_ip : nodeAdd.IP,
              parent : scan_data.vlan,
            },
          }
        );
      }
    });

    // liaison de l'ensemble des entités nmap à la gateway : 
    let gateway_id = (scan_data.local_data.gateway_ip + '\n' + scan_data.local_data.gateway_mac);
    nodes.forEach(function(nodeI) {
      if((nodeI.data.type == 'IP') && (nodeI.data.id != gateway_id)) { // on évite de créer un lien entre autre chose qu'une IP et la gateway
        edges.push(
          {
            group:'edges',
            data : {
              id : ('link ' + gateway_id + " " + nodeI.data.id + " "),
              source : nodeI.data.id,
              target : (scan_data.local_data.gateway_ip + '\n' + scan_data.local_data.gateway_mac),
              type: 'IPtoVLAN',
              parent : scan_data.vlan,
            }
          }
        );
      }
    });

    // on ajoute l'ensemble des ip au graph
    $scope.cyto.add(nodes);
    // on ajoute l'ensemble des lien au graph
    $scope.cyto.add(edges);
    // on actualise la vue
    $scope.layout = $scope.cyto.layout($scope.options);
    $scope.layout.run();
  };

  // fonction de création du graph à partir d'un scan trace
  $scope.createCytoTraceGraph = function(scan_data) {
    console.log(scan_data);
    let nodes = [];
    let edges = [];

    // on ajoute les noeuds
    scan_data.scan.forEach(function(ipdata){
      let ip = ipdata[0];
      // on récupère le node déjà créé avec l'ip associé : 
      let node_exist = $scope.cyto.elements('node[data_ip = "' + ip + '"]');
      if(node_exist.length == 0) { // cas où le noeud est à créer
        nodes.push(
          {
            group:'nodes',
            data: {
              id : (ip),
              label : (ip),
              type : 'IP',
              typeip : ipaddr.parse(ip).range(),
              data : {'ip' : ip},
              data_ip : ip,
              parent : $scope.getVLANByIP(ip), // a retravailler : on doit préalablement voir si le noeud rentre dans le CIDR...
            },
          }
        );
      }else { // cas où le noeud existe déjà

      }
    });

    // on ajoute l'ensemble des ip au graph
    $scope.cyto.add(nodes);

    // on ajoute les liens si possible
    for(let key in scan_data.scan){
      if(key == 0) {
      }else {
        let id_last_node = $scope.getNodeIdByIP(scan_data.scan[key-1][0]);
        let id_node = $scope.getNodeIdByIP(scan_data.scan[key][0]);
        edges.push({
          group:'edges',
          data : {
            id : ('link ' + id_last_node + " " + id_node + " "),
            source : id_last_node,
            target : id_node,
            type : 'traceroute',
          }
        });
      }
    }

    // on ajoute l'ensemble des lien au graph
    $scope.cyto.add(edges);
    // on actualise la vue
    $scope.layout = $scope.cyto.layout($scope.options);
    $scope.layout.run();

    // on va maintenant lier les données aux AS 
    // NOTE : c'est une opération longue, si on parviens à la réduire à un temps raisonnable,
    // le code sera à fusionner avec le code d'au dessus...
    scan_data.scan.forEach(function(ipdata) {
      let nodeAS = [];
      let nodeVlan = [];
      let ip = ipdata[0];
      let cidr = ipdata[1][0];
      let as_number = ipdata[1][1];
      let typeip = ipaddr.parse(ip).range();
      if((typeip != 'private') && (typeip != 'multicast')) {
        // on crée un AS
        nodeAS.push(
          {
            group:'nodes',
            data: {
              id : as_number,
              label : as_number,
              type : 'AS',
            },
          }
        );
        // on crée un VLAN
        nodeVlan.push(
          {
            group:'nodes',
            data: {
              id : cidr,
              label : cidr,
              type : 'VLAN',
              parent: as_number,
            },
          }
        );
      }
      // on ajoute l'ensemble des VLAN + AS au graph
      $scope.cyto.add(nodeAS);
      $scope.cyto.add(nodeVlan);
      // on ajoute l'ID du node audit VLAN
      $scope.cyto.$('#' + $scope.getNodeIdByIP(ip)).move({parent : $scope.getVLANByIP(ip)});
    });
    // on actualise la vue
    $scope.layout = $scope.cyto.layout($scope.options);
    $scope.layout.run();
  };

  // fonction de création du graph à partir d'un scan trace CIDR
  $scope.createCytoTraceCIDRGraph = function(scan_data) {
    scan_data.scan.forEach(function(trace) { // l'arnaque se situe ici (vous avez cru quoi ? que j'allais tout recoder ?)
      $scope.createCytoTraceGraph({'scan': trace});
    })
  };

  // fonction de création du graph à partir d'un scan CIDR normé (par exemple DHCP)
  $scope.createCytoCIDRGraph = function(scan_data, cidr) {
    if(scan_data.scan.length == 0) { // on vérifie qu'on a pas juste un scan vide
      $scope.$parent.sendToastData('Graphe', "Scan reçu vide", 'echo_toast_info');
      return;
    }
    // on commence la création de la vue graphe
    let nodes = [];
    let edges = [];
    //ajout de la représentation du VLAN
    nodes.push(
      {
        group:'nodes',
        data: {
          id : cidr,
          label : cidr,
          type : 'VLAN',
        },
      }
    );

    // ajout des entités nmap :
    scan_data.scan.forEach(function(nodeAdd) {
      if(nodeAdd.mac != undefined) { nodeAdd.mac = nodeAdd.mac.toLowerCase(); };
      nodes.push(
        {
          group:'nodes',
          data: {
            id : (nodeAdd.ipv4 + '\n' + nodeAdd.mac),
            label : (nodeAdd.ipv4 + '\n' + nodeAdd.mac),
            type : 'IP',
            typeip : ipaddr.parse(nodeAdd.ipv4).range(),
            data : nodeAdd,
            data_ip : nodeAdd.ipv4,
            parent : cidr,
          },
        }
      );
    });

    // on ajoute l'ensemble des ip au graph
    $scope.cyto.add(nodes);
    // on ajoute l'ensemble des lien au graph
    $scope.cyto.add(edges);
    // on actualise la vue
    $scope.layout = $scope.cyto.layout($scope.options);
    $scope.layout.run();
  };

  // fonction de création du graph à partir d'un scan d'une IP ressortant les services
  $scope.createCytoServiceGraph = function(scan_data) {
    // on crée les listes de noeuds/liens qu'on va pousser dans le graph
    let nodes_services = [];
    let edges_services = [];

    scan_data.forEach(function(ip_scanned) {
        // on cherche le noeud auquel rattacher les services
      let node_update = $scope.cyto.elements("node[data_ip = '" + ip_scanned.IP + "']");
      // on crée les noeuds de type services associés au noeud IP
      if(node_update.length != 0) { // on vérifie qu'on a trouvé l'IP (on sais jamais)
        // on accède aux données listés 
        let id_node = (ip_scanned.IP + ':' + ip_scanned.port + ' ' + ip_scanned.result.cpe);
        let label_node = ip_scanned.port + ' ' + ip_scanned.result.product;
        if(ip_scanned.result.product == "") {
          label_node = ip_scanned.port + ' ' + ip_scanned.result.name;
        }
        nodes_services.push(
          {
            group:'nodes',
            data: {
              id : id_node,
              label : label_node,
              type : 'Service',
              data : ip_scanned.result,
              data_ip : ip_scanned.IP,
              parent : node_update.data('parent'),
            },
          }
        );
        edges_services.push(
          {
            group:'edges',
            data : {
              id : ('link ' + node_update.data('id') + " " + id_node + " "),
              source : node_update.data('id'),
              target : id_node,
              type: 'ServicetoIP',
              parent : node_update.data('parent'),
            }
          }
        );
      }
    });
    // on ajoute l'ensemble des services au graph
    $scope.cyto.add(nodes_services);
    // on ajoute l'ensemble des lien au graph
    $scope.cyto.add(edges_services);
    // on actualise la vue
    $scope.layout = $scope.cyto.layout($scope.options);
    $scope.layout.run();
  };

  // fonction de mise à jour d'un noeud spécifique
  $scope.updateNodebyIP = function(ip_node, update_key, update_data) {
    // on cherche le noeud à updater par IP
    let node_update = $scope.cyto.elements("node[data_ip = '" + ip_node + "']");
    // on met la donnée dans la key du node depuis data
    if(node_update.length != 0) {
      node_update.data('data')[update_key] = update_data;
    }
  };

  //fonction d'ajout du profiling à l'OS
  $scope.updateNodeOS = function(ip_node, profiling_data) {
    let node_update = $scope.cyto.elements("node[data_ip = '" + ip_node + "']");
    // on vérifie que le noeud existe avant d'y ajouter des choses
    if(node_update.length != 0) {
      node_update.data('data')['OS'] = profiling_data.osfamily;
    }
  }

  // fonction de récupération d'un ID de node via une recherche par IP
  $scope.getNodeIdByIP = function(ip) {
    return $scope.cyto.elements('node[data_ip = "' + ip + '"]').data('id');
  };

  // Fonction de récupération d'un VLAN via une recherche par IP
  $scope.getVLANByIP = function(ip) {
    let listVLAN = [];
    $scope.cyto.elements('node[type = "VLAN"]').forEach(function(node) {
      listVLAN.push(node.data('id').split('/'));
    });

    // on trie les subnet par ordre de taille 
    listVLAN.sort(function(a, b){return b[1] - a[1]});
    
    // maintenant, on doit comparer IP / range d'IP et le premier match renvoie son ID
    for (const element of listVLAN) {
      if(ipaddr.parse(ip).match(ipaddr.parse(element[0]), element[1])) {
        return element[0] + "/" + element[1];
      }
    }
  };

  // évènement en cas de clic sur un noeud :
	$scope.cyto.on('tap', 'node', function(evt){
		// on envoie au parent le noeud à afficher :
		$scope.$parent.$broadcast("updatePanelNodeData", evt.target.data(), evt.target.data('type'));
	});

  // évènement en cas de double clic sur le fond
	$scope.cyto.on('dblclick', function(evt){
    console.log('double clic reset panels')
		// on envoie au parent le noeud à afficher :
		$scope.$parent.$broadcast("resetPanels");
	});

  $scope.$on('request_scan', function(event, args) {
    if($scope.listScanFunc.hasOwnProperty(args.callScan)) {
      if(args.hasOwnProperty('texte')) {
        $scope.listScanFunc[args.callScan](args.cible, args.titre, args.texte);
      }else if(args.hasOwnProperty('port_end')) {
        $scope.listScanFunc[args.callScan](args.cible, args.port_start, args.port_end);
      }else if (args.hasOwnProperty('cible')) {
        $scope.listScanFunc[args.callScan](args.cible);
      }else {
        $scope.listScanFunc[args.callScan]();
      }
    }
  });

  $scope.$on('request_export_png', function(event, args) {
    console.log("lancement d'un export PNG");
    $scope.getCytoPNG();
  });

  $scope.$on('request_export_jpg', function(event, args) {
    console.log("lancement d'un export JPG");
    $scope.getCytoJPG();
  });

  $scope.$on('request_export_json', function(event, args) {
    console.log("lancement d'un export JSON");
    $scope.getCytoJSON();
  });

  $scope.$on('request_import_json', function(event, args) {
    console.log("lancement d'un import JSON");
    //console.log(args)
    $scope.setCytoJSON(JSON.parse(args.file));
  });

  $scope.$on('request_actualise_graph', function(event, args) {
    // on actualise la vue
    $scope.layout = $scope.cyto.layout($scope.options);
    $scope.layout.run();
  });

  $scope.$on('request_delete_selection', function(event, args) {
    $scope.cyto.elements('node:selected').remove();
  });

  $scope.getCytoPNG = function() {
    $scope.cyto.png({output : 'blob-promise'}).then(function(data) {
      let element = document.createElement('a');
      element.setAttribute('href', window.URL.createObjectURL(data));
      element.setAttribute('download', "graph.png");
      element.style.display = 'none';
      document.body.appendChild(element);
    
      element.click();
    
      document.body.removeChild(element);
    }).catch(function(error ) {
      console.log(error);
    });
  };

  $scope.getCytoJPG = function() {
    $scope.cyto.jpg({output : 'blob-promise'}).then(function(data) {
      let element = document.createElement('a');
      element.setAttribute('href', window.URL.createObjectURL(data));
      element.setAttribute('download', "graph.jpg");
      element.style.display = 'none';
      document.body.appendChild(element);
    
      element.click();
    
      document.body.removeChild(element);
    }).catch(function(error ) {
      console.log(error);
    });
  };

  $scope.getCytoJSON = function() {
    let element = document.createElement('a');
    element.setAttribute('href', 'data:application/json;charset=utf-8,' + encodeURIComponent(JSON.stringify($scope.cyto.json())));
    element.setAttribute('download', "graph.json");
    element.style.display = 'none';
    document.body.appendChild(element);
  
    element.click();
  
    document.body.removeChild(element);
  };

  $scope.setCytoJSON = function(param_json) {
    $scope.cyto.json(param_json);
  };

  $scope.$on('reloadStyle', function(event, args) {
    $scope.loadStyle();
  })

  // binder de clavier qui va récupérer l'ensemble des touches du clavier pour 
  // automatiser la gestion d'une partie du graph
  $document.bind('keyup', function (e) {
    if(e.keyCode === 46 | e.keyCode === 8) { // touche SUPPR/DEL
      $scope.cyto.elements('node:selected').remove();
    }
  });

  console.log($scope.cyto)
});

angular.element(document).ready(function() {
	angular.bootstrap(document, [ 'EchoApp' ]);
});