let EchoApp = angular.module('EchoApp', ['ngAnimate']);

EchoApp.controller("ParentCtrl", function($scope, $http) {
  $scope.sendToastData = function(titre, texte) {
    $scope.$broadcast('ToastMessage', {
      'titre' : titre,
      'texte' : texte,
    })
  };

  // vérification d'accessibilité du backend : 
  $scope.getHealth = function() {
    let req = {
      method : 'GET',
      url : '/json/health',
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.sendToastData('Echosounder', "API fonctionnelle");
      },
      // si la requête échoue :
      function(error) {
        $scope.sendToastData('Echosounder', "API erreur : " + error);
        console.log(error);
      }
    );
  };

  $scope.getHealth();

  // variable de sélection multiple de noeuds pour scan
  $scope.nodesSelected = [];
});

EchoApp.controller("leftPanelMenu", function($scope, $rootScope, $http) {
  $scope.showMenu1 = false;
  $scope.showMenu2 = false;
  $scope.showMenu3 = false;
  $scope.portShow = false;


  $scope.cible = "192.168.1.0/24";

  $scope.machineCible = "0.0.0.0"
  $scope.portStart = "0"
  $scope.portEnd = "400"


  $scope.clickFastPing = function() {
    console.log("emit fast ping request");
    $rootScope.$broadcast('request_scan', {'cible' : $scope.cible, 'callScan' : 'request_fast_ping'});
  }

  $scope.clickScanARP = function() {
    console.log("emit arp scan request");
    $rootScope.$broadcast('request_scan', {'cible' : $scope.cible, 'callScan' : 'request_arp_scan'});
  }

  $scope.clickScanCIDRTraceroute = function() {
    console.log("emit trace cidr scan request");
    $rootScope.$broadcast('request_scan', {'cible' : $scope.cible, 'callScan' : 'request_traceroute_cidr_scan'});
  }

  $scope.clickTraceroute = function() {
    console.log("emit trace scan request");
    $rootScope.$broadcast('request_scan', {'callScan' : 'request_traceroute_scan'});
  }

  $scope.clickTracerouteLocal = function() {
    console.log("emit trace local scan request");
    $rootScope.$broadcast('request_scan', {'callScan' : 'request_traceroute_local_scan'});
  }

  $scope.clickScanProfiling = function() {
    console.log("emit profiling scan request");
    $rootScope.$broadcast('request_scan', {'cible' : $scope.machineCible, 'callScan' : 'request_profiling_scan'});
  }

  $scope.clickScanServices = function() {
    if ($scope.portShow){
      console.log("emit services scan request");
      $rootScope.$broadcast('request_scan', {'cible' : $scope.machineCible, 'port_start' : $scope.portStart, 'port_end' : $scope.portEnd, 'callScan' : 'request_services_scan'});
    }else{
      $scope.portShow = true;
    }
  }

  $scope.clickScanFastServices = function() {
    console.log("emit services fast scan request");
    $rootScope.$broadcast('request_scan', {'cible' : $scope.machineCible, 'callScan' : 'request_services_fast_scan'});
  }

  $scope.clickScanReversePTR = function() {
    console.log("emit reverse PTR scan request");
    $rootScope.$broadcast('request_scan', {'cible' : $scope.machineCible, 'callScan' : 'request_reverse_ptr_scan'});
  }

  $scope.clickScanSSHFingerprint = function() {
    console.log("emit fingerprint SSH scan request");
    $rootScope.$broadcast('request_scan', {'cible' : $scope.machineCible, 'callScan' : 'request_fingerprint_ssh_scan'});
  }

  $scope.clickScanSMB = function() {
    console.log("emit SMB scan request");
    $rootScope.$broadcast('request_scan', {'cible' : $scope.machineCible, 'callScan' : 'request_smb_scan'});
  }

  $scope.clickScanSNMP = function() {
    console.log("emit SNMP scan request");
    $rootScope.$broadcast('request_scan', {'cible' : $scope.machineCible, 'callScan' : 'request_snmp_scan'});
  }

  $scope.clickScanSNMPnetstat = function() {
    console.log("emit SNMP scan request");
    $rootScope.$broadcast('request_scan', {'cible' : $scope.machineCible, 'callScan' : 'request_snmp_netstat_scan'});
  }

  $scope.clickScanSNMPprocess = function() {
    console.log("emit SNMP scan request");
    $rootScope.$broadcast('request_scan', {'cible' : $scope.machineCible, 'callScan' : 'request_snmp_process_scan'});
  }
  
  $scope.clickScanRDP = function() {
    console.log("emit RDP scan request");
    $rootScope.$broadcast('request_scan', {'cible' : $scope.machineCible, 'callScan' : 'request_rdp_scan'});
  }

  $scope.clickScanTracerouteCible = function() {
    console.log("emit traceroutecible scan request");
    $rootScope.$broadcast('request_scan', {'cible' : $scope.machineCible, 'callScan' : 'request_trace_cible_scan'});
  }

  $scope.clickResolveAS = function() {
    console.log("emit resolve AS scan request");
    $rootScope.$broadcast('request_scan', {'callScan' : 'request_resolve_as_scan'});
  }

  $scope.getSelectionScan = function() {
    console.log("emit get selection request");
    $rootScope.$broadcast('request_scan', {'callScan' : 'request_selection_scan'});
  }

  $scope.deleteIPSelected = function(ip) {
    let index = $scope.$parent.nodesSelected.indexOf(ip);
    if(index != -1) {
      $scope.$parent.nodesSelected.splice(index, 1);
    }
  };

  $scope.$on('updatePanelNodeData',function(event, nodedata, nodetype) {
    if(nodetype == 'IP') { // on prend que les IP
      $scope.machineCible = nodedata.data_ip;
      $scope.$apply();
    }else if (nodetype == 'VLAN') {
      $scope.cible = nodedata.id;
      $scope.$apply();
    }
  });

  $scope.$parent.$watch('nodesSelected', function(test) {
    console.log(test);
  });


});

EchoApp.controller("rightPanelMenu", function($scope, $rootScope, $http) {
  $scope.showMenu1 = false;
  $scope.showMenu2 = false;
  $scope.showMenu3 = false;

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
  }

  $scope.exportPNG = function() {
    $rootScope.$broadcast('request_export_png', {});
  };

  $scope.exportJPG = function() {
    $rootScope.$broadcast('request_export_jpg', {});
  };

  $scope.exportJSON= function() {
    $rootScope.$broadcast('request_export_json', {});
  };

  $scope.importJSON= function() {
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
    });
  });

  // fonction de trigger de watch tant que $scope.listToast n'est pas vide
  $scope.$watchCollection('listToast', function(newListToard, oldListToad) {
    if(newListToard.length == 0) {
      // on ne fait rien
    }else {
      // place un delay de 3 secondes plus on efface le premier élément de la liste
      $timeout(function() { $scope.listToast = $scope.listToast.slice(1);}, 5000);
    }
  })
});

EchoApp.controller("graphNetwork", function($scope, $rootScope, $http) {
  // fonctions de récupérations de donnée Fast Scan
  $scope.getFastScan = function(cible) {
    $scope.$parent.sendToastData('FastPing', "lancement d'un scan");
    let req = {
      method : 'POST',
      url : '/json/fast_scan',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };
    
    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('FastPing', "réception d'un scan");
        console.log(response.data);
        // on appel la fonction de création de graphs :
        $scope.createCytoVlanGraph(response.data);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('FastPing', "erreur : " + error);
        console.log(error);
      }
    );
  };

  // fonctions de récupération de donnée scan ARP
  $scope.getARPScan = function(cible) {
    $scope.$parent.sendToastData('ARP Scan', "lancement d'un scan");
    let req = {
      method : 'POST',
      url : '/json/arp_scan',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('ARP Scan', "réception d'un scan");
        console.log(response.data);
        // on appel la fonction de création de graphs :
        $scope.createCytoVlanGraph(response.data);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('ARP Scan', "erreur Scan : " + error);
        console.log(error);
      }
    );
  };

  // fonction d'obtention d'IP du réseau local (ou opérateur) via traceroute CIDR
  $scope.getTracerouteCIDRScan = function(cible) {
    $scope.$parent.sendToastData('Traceroute CIDR Scan', "lancement d'un scan");
    let req = {
      method : 'POST',
      url : '/json/trace_cidr_scan',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('Traceroute CIDR Scan', "réception d'un scan");
        console.log(response.data);
        // on appel la fonction de création de graphs :
        $scope.createCytoTraceCIDRGraph(response.data);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('Traceroute CIDR Scan', "erreur Scan : " + error);
        console.log(error);
      }
    );
  }

  // fonction d'obtention d'IP du réseau local (ou opérateur) via traceroute
  $scope.getTracerouteScan = function() {
    $scope.$parent.sendToastData('Traceroute Scan', "lancement d'un scan");
    let req = {
      method : 'GET',
      url : '/json/trace_scan',
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('Traceroute Scan', "réception d'un scan");
        console.log(response.data);
        // on appel la fonction de création de graphs :
        $scope.createCytoTraceGraph(response.data);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('Traceroute Scan', "erreur Scan : " + error);
        console.log(error);
      }
    );
  };

  // fonction d'obtention d'IP des réseaux locaux (ou opérateurs) via traceroute
  $scope.getTracerouteLocalScan = function() {
    $scope.$parent.sendToastData('Traceroute Local Scan', "lancement d'un scan");
    let list_local_cidr = [
        "0.0.0.0/8", 
        "100.64.0.0/10",
        "127.0.0.0/8", 
        "169.254.0.0/16", 
        "192.0.0.0/24", 
        "192.0.2.0/24", 
        "192.88.99.0/24",
        "198.18.0.0/15", 
        "198.51.100.0/24", 
        "203.0.113.0/24",
        "224.0.0.0/4", 
        "233.252.0.0/24", 
        "240.0.0.0/4", 
        "255.255.255.255/32",
    ];
    list_local_cidr.forEach(function(cidr) {
      let req = {
        method : 'POST',
        url : '/json/trace_cidr_scan',
        headers: {'Content-Type': 'application/json'},
        data : {'cible' : cidr},
      }
  
      $http(req).then(
        // si la requête passe :
        
        function(response) {
          $scope.$parent.sendToastData('Traceroute Local Scan', "réception d'un scan");
          console.log(response.data);
          // on appel la fonction de création de graphs :
          $scope.createCytoTraceCIDRGraph(response.data);
        },
        // si la requête échoue :
        function(error) {
          $scope.$parent.sendToastData('Traceroute Local Scan', "erreur Scan : " + error);
          console.log(error);
        }
      );
    });
  };

  // fonctions de profiling machine (OS, device, ...)
  $scope.getProfilingScan = function(cible) {
    $scope.$parent.sendToastData('Profiling', "lancement d'un scan");
    let req = {
      method : 'POST',
      url : '/json/profiling_scan',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('Profiling Scan', "réception d'un scan");
        console.log(response.data);
        // on met à jour le node concerné via une fonction de sélection de node
        $scope.updateNodebyIP(cible, 'profiling', response.data['scan']);
        $scope.updateNodeOS(cible, response.data['scan']);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('Profiling Scan', "erreur Scan : " + error);
        console.log(error);
      }
    );
  };

  // fonctions de listage des services machine (par port)
  $scope.getServicesScan = function(cible, pstart, pend) {
    $scope.$parent.sendToastData('Services', "lancement d'un scan");
    let req = {
      method : 'POST',
      url : '/json/services_scan',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible, 'port_start' : pstart, 'port_end' : pend},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('Services Scan', "réception d'un scan");
        console.log(response.data);
        // on met à jour le graph en ajoutant des noeuds type service lié à la cible
        $scope.createCytoServiceGraph(response.data['scan']);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('Services Scan', "erreur Scan : " + error);
        console.log(error);
      }
    );
  };

  // fonctions de listage des services machine (par port)
  $scope.getServicesFastScan = function(cible) {
    $scope.$parent.sendToastData('Services', "lancement d'un fast scan");
    let req = {
      method : 'POST',
      url : '/json/services_fast_scan',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('Services Fast Scan', "réception d'un scan");
        console.log(response.data);
        // on met à jour le graph en ajoutant des noeuds type service lié à la cible
        $scope.createCytoServiceGraph(response.data['scan']);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('Services Fast Scan', "erreur Scan : " + error);
        console.log(error);
      }
    );
  };

  // fonction d'obtention du hostname par requête DNS reverse PTR sur cible
  $scope.getReversePTRScan = function(cible) {
    $scope.$parent.sendToastData('Reverse PTR', "lancement d'un scan");
    let req = {
      method : 'POST',
      url : '/json/reverse_ptr_scan',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('Reverse PTR Scan', "réception d'un scan");
        console.log(response.data);
        // on met à jour le node concerné via une fonction de sélection de node
        $scope.updateNodebyIP(cible, 'hostname PTR', response.data['scan']);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('Reverse PTR Scan', "erreur Scan : " + error);
        console.log(error);
      }
    );
  };

  // fonction d'obtention de fingerprint SSH par requête SSH sur cible
  $scope.getFingerprintSSHScan = function(cible) {
    $scope.$parent.sendToastData('Fingerprint SSH', "lancement d'un scan");
    let req = {
      method : 'POST',
      url : '/json/fingerpting_ssh_scan',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('Fingerprint SSH Scan', "réception d'un scan");
        console.log(response.data);
        // on met à jour le node concerné via une fonction de sélection de node
        $scope.updateNodebyIP(cible, 'fingerprint ssh', response.data['scan']);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('Fingerprint SSH Scan', "erreur Scan : " + error);
        console.log(error);
      }
    );
  };

  $scope.getSMBScan = function(cible) {
    $scope.$parent.sendToastData('SMB', "lancement d'un scan");
    let req = {
      method : 'POST',
      url : '/json/scan_info_smb',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('SMB Scan', "réception d'un scan");
        console.log(response.data);
        // on met à jour le node concerné via une fonction de sélection de node
        $scope.updateNodebyIP(cible, 'smb', response.data['scan']);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('SMB Scan', "erreur Scan : " + error);
        console.log(error);
      }
    );
  }

  $scope.getSNMPScan = function(cible) {
    $scope.$parent.sendToastData('SNMP info', "lancement d'un scan");
    let req = {
      method : 'POST',
      url : '/json/scan_snmp_info',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('SNMP Scan', "réception d'un scan");
        console.log(response.data);
        // on met à jour le node concerné via une fonction de sélection de node
        $scope.updateNodebyIP(cible, 'snmp_info', response.data['scan']);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('SNMP Scan', "erreur Scan : " + error);
        console.log(error);
      }
    );
  }

  $scope.getSNMPnetstatScan = function(cible) {
    $scope.$parent.sendToastData('SNMP netstat', "lancement d'un scan");
    let req = {
      method : 'POST',
      url : '/json/scan_snmp_netstat',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('SNMP netstat', "réception d'un scan");
        console.log(response.data);
        // on met à jour le node concerné via une fonction de sélection de node
        $scope.updateNodebyIP(cible, 'snmp_nestat', response.data['scan']);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('SNMP netstat', "erreur Scan : " + error);
        console.log(error);
      }
    );
  };

  $scope.getSNMPprocessScan = function(cible) {
    $scope.$parent.sendToastData('SNMP process', "lancement d'un scan");
    let req = {
      method : 'POST',
      url : '/json/scan_snmp_processes',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('SNMP process', "réception d'un scan");
        console.log(response.data);
        // on met à jour le node concerné via une fonction de sélection de node
        $scope.updateNodebyIP(cible, 'snmp_process', response.data['scan']);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('SNMP process', "erreur Scan : " + error);
        console.log(error);
      }
    );
  };

  $scope.getRDPScan = function(cible) {
    $scope.$parent.sendToastData('RDP', "lancement d'un scan");
    let req = {
      method : 'POST',
      url : '/json/scan_rdp_info',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('RDP Scan', "réception d'un scan");
        console.log(response.data);
        // on met à jour le node concerné via une fonction de sélection de node
        $scope.updateNodebyIP(cible, 'rdp_info', response.data['scan']);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('RDP Scan', "erreur Scan : " + error);
        console.log(error);
      }
    );
  }

  $scope.getTraceCibleScan = function(cible) {
    $scope.$parent.sendToastData('trace cible', "lancement d'un scan");
    let req = {
      method : 'POST',
      url : '/json/trace_scan',
      headers: {'Content-Type': 'application/json'},
      data : {'cible' : cible},
    };

    $http(req).then(
      // si la requête passe :
      
      function(response) {
        $scope.$parent.sendToastData('TraceCible Scan', "réception d'un scan");
        console.log(response.data);
        // on met à jour le node concerné via une fonction de sélection de node
        $scope.createCytoTraceGraph(response.data);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('TraceCible Scan', "erreur Scan : " + error);
        console.log(error);
      }
    );
  }

  $scope.getResolveAS = function() {
    $scope.cyto.elements('node[type = "AS"]').forEach(function(node) {
      if(node.data('as_resolution')){
        return; // si la résolution à déjà été faite, on s'épargne de la refaire
      }
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
          $scope.$parent.sendToastData('AS Resolution', "Récupération de donnée RDAP");
          console.log(response.data);
          // on les fout dans le label du noeud
          node.data('label', node.data('label') + " " + response.data.name);
          // on spécifie que la résolution a été effectué
          node.data('as_resolution', true);
        },
        // si la requête échoue :
        function(error) {
          $scope.$parent.sendToastData('AS Resolution', "erreur : " + error);
          console.log(error);
        }
      );
    });
  }

  // fonction de récupération des IP à scanner pour le panel de scan d'ip.
  $scope.getSelectionScan = function() {
    let list_ip = [];
    $scope.cyto.elements('node[type="IP"]:selected').forEach(function(node) {
      list_ip.push(node.data('data_ip'));
    });
    $scope.$parent.nodesSelected = list_ip;
  };

  // association requête vers nom de fonction
  $scope.listScanFunc = {
    'request_fast_ping' : $scope.getFastScan,
    'request_arp_scan' : $scope.getARPScan ,
    'request_traceroute_cidr_scan' : $scope.getTracerouteCIDRScan ,
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
    'request_rdp_scan' : $scope.getRDPScan,
    'request_trace_cible_scan' : $scope.getTraceCibleScan,
    'request_resolve_as_scan': $scope.getResolveAS,
    'request_selection_scan': $scope.getSelectionScan,
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

  $scope.styles = [
    {
      selector: 'node',
      css: {
        'shape' : 'octagon',
        'color' : '#abd6db',
        'background-color' : '#102324', // --fond-color-tres-noir-bleue
        'border-style' : 'none',
        'content': 'data(label)', // méga important, détermine quoi afficher comme donnée dans le label de noeud
        'text-outline-color': '#080808',
        'text-outline-width' : 1,
        'text-valign': 'top',
        'text-halign': 'center',
        'opacity' : 1,
        'text-wrap': 'wrap',
        'background-fit' : 'contain',
        'font-family' : 'Hack',
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
      },
    },
    {
      selector: 'node:selected',
      css: {
        'border-width' : 2,
        'border-style' : 'solid',
        'border-color' : '#3e908e', // --widget-blue1
        'ghost' : 'yes',
        "ghost-offset-y": 1,
        'ghost-opacity': 0.4,
      },
    },
    {
      selector: 'edge',
      css: {
        'line-color' : '#4b948c', // --widget-blue3
        'target-arrow-color' : '#5c202a', // --widget-red1
        'curve-style': 'bezier',
        'target-arrow-shape': 'triangle',
        'opacity' : 0.5,
      },
    },
  ];
  $scope.cyto.style($scope.styles);

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
  }

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
  }

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

  $scope.$on('request_scan', function(event, args) {
    if($scope.listScanFunc.hasOwnProperty(args.callScan)) {
      if(args.hasOwnProperty('port_end')) {
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
    console.log(args)
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

  console.log($scope.cyto)
});

angular.element(document).ready(function() {
	angular.bootstrap(document, [ 'EchoApp' ]);
});