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
    $rootScope.$broadcast('request_fast_ping', {'cible' : $scope.cible});
  }

  $scope.clickScanARP = function() {
    console.log("emit arp scan request");
    $rootScope.$broadcast('request_arp_scan', {'cible' : $scope.cible});
  }

  $scope.clickTraceroute = function() {
    console.log("emit trace scan request");
    $rootScope.$broadcast('request_traceroute_scan', {});
  }

  $scope.clickScanProfiling = function() {
    console.log("emit profiling scan request");
    $rootScope.$broadcast('request_profiling_scan', {'cible' : $scope.machineCible});
  }

  $scope.clickScanServices = function() {
    if ($scope.portShow){
      console.log("emit services scan request");
      $rootScope.$broadcast('request_services_scan', {'cible' : $scope.machineCible, 'port_start' : $scope.portStart, 'port_end' : $scope.portEnd});
    }else{
      $scope.portShow = true;
    }
  }

  $scope.clickScanReversePTR = function() {
    console.log("emit reverse PTR scan request");
    $rootScope.$broadcast('request_reverse_ptr_scan', {'cible' : $scope.machineCible});
  }

  $scope.$on('updatePanelNodeData',function(event, nodedata, nodetype) {
    if(nodetype == 'IP') { // on prend que les IP
      $scope.machineCible = nodedata.data_ip;
      $scope.$apply();
    }else if (nodetype == 'VLAN') {
      $scope.cible = nodedata.id;
      $scope.$apply();
    }
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
      // on demande à angularJS d'actualiser sa vue
      $scope.$apply();
    }else if(typenode == 'Service') {
      $scope.servicedata = node.data;
      $scope.showMenu1 = false;
      $scope.showMenu2 = true;
      $scope.showMenu3 = false;
      // on demande à angularJS d'actualiser sa vue
      $scope.$apply();
    }else {
      // on fais rien si on reconnais pas le type de noeud
    }
  });

  $scope.checkAPI = function() {
    $scope.$parent.getHealth();
  }

  $scope.exportJSON= function() {
    $rootScope.$broadcast('request_export_json', {});
  };

  $scope.importJSON= function() {
    document.getElementById('echo_json_upload').click();
    let f = document.getElementById('echo_json_upload').files[0],
        r = new FileReader();

    r.onloadend = function(e) {
      let data = e.target.result;
      // On envoie le fichier
      $rootScope.$broadcast('request_import_json', {'file' : data});
    }

    r.readAsBinaryString(f);
  };

  $scope.actualiseGraph = function() {
    // on fait une demande d'actualisation du graph : 
    $rootScope.$broadcast('request_actualise_graph', {});
  }
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

  // fonction d'obtention d'IP privées via traceroute
  $scope.getTracerouteScan = function() {
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

  // fonctions de profiling machine (OS, device, ...)
  $scope.getProfilingScan = function(cible) {
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

  // fonction d'obtention du hostname par requête DNS reverse PTR sur cible
  $scope.getReversePTRScan = function(cible) {
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

  // partie gestion du graph
  $scope.cyto = cytoscape({
		container: document.getElementById('mynetwork')
	});

  $scope.options = {
		name: 'fcose', // cose est quand même pas mal...
		fit: true,  // Whether to fit the network view after when done
		padding: 10,
		animate: true, // TODO : l'animation est constante, mais la force n'est pas recalculé, trouvé un moyen pour que ça soit le cas
		animationDuration: 1000,
		animationEasing: 'ease-out',
		//infinite: 'end', // OW SHI__
		nodeDimensionsIncludeLabels: true, // OUUUIIIIII
		randomize: false, // ça semble mettre les noeud dans leur ordre d'arrivée, ça me plait.
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
      },
    },
    {
      selector: 'node[type = "VLAN"]',
      css: {
        'text-valign': 'top',
        'text-halign': 'center',
        'background-opacity': '0',
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
    scan_data.scan.forEach(function(ip) {
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
    scan_data.scan.reduce( // cette sorcellerie vise à sortir les noeuds 2 à 2
      function(accumulator, currentValue, currentIndex, array) {
        if (currentIndex % 2 === 0)
          accumulator.push(array.slice(currentIndex, currentIndex + 2));
        return accumulator;
      }, []
    ).map(p => (edges.push({
      group:'edges',
      data : {
        id : ('link ' + p[0] + " " + p[1] + " "),
        source : $scope.getNodeIdByIP(p[0]),
        target : $scope.getNodeIdByIP(p[1]),
      }
    })));

    // on ajoute l'ensemble des lien au graph
    $scope.cyto.add(edges);
    // on actualise la vue
    $scope.layout = $scope.cyto.layout($scope.options);
    $scope.layout.run();
  };

  // fonction de création du graph à partir d'un scan d'une IP ressortant les services
  $scope.createCytoServiceGraph = function(scan_data) {
    scan_data.forEach(function(ip_scanned) {
        // on cherche le noeud auquel rattacher les services
      let node_update = $scope.cyto.elements("node[data_ip = '" + ip_scanned.IP + "']");
      // on crée les noeuds de type services associés au noeud IP
      if(node_update.length != 0) { // on vérifie qu'on a trouvé l'IP (on sais jamais)
        // on crée les listes de noeuds/liens qu'on va pousser dans le graph
        let nodes_services = [];
        let edges_services = [];
        // on accède aux données listés par protocol
        for (const [protocol, protocolObjects] of Object.entries(ip_scanned.protocols)) {
          // on accède aux données listés par port
          for (const [port, portObjects] of Object.entries(protocolObjects)) {
            let id_node = (ip_scanned.IP + ':' + port + ' ' + portObjects.cpe);
            let label_node = port + ' ' + portObjects.product;
            if(portObjects.product == "") {
              label_node = port + ' ' + portObjects.name;
            }
            nodes_services.push(
              {
                group:'nodes',
                data: {
                  id : id_node,
                  label : label_node,
                  type : 'Service',
                  data : portObjects,
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
                  parent : node_update.data('parent'),
                }
              }
            );
          };
        };
        // on ajoute l'ensemble des services au graph
        $scope.cyto.add(nodes_services);
        // on ajoute l'ensemble des lien au graph
        $scope.cyto.add(edges_services);
        // on actualise la vue
        $scope.layout = $scope.cyto.layout($scope.options);
        $scope.layout.run();
      }
    });
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

  $scope.getNodeIdByIP = function(ip) {
    return $scope.cyto.elements('node[data_ip = "' + ip + '"]').data('id');
  };

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
  }

  // évènement en cas de clic sur un noeud :
	$scope.cyto.on('tap', 'node', function(evt){
		// on envoie au parent le noeud à afficher :
		$scope.$parent.$broadcast("updatePanelNodeData", evt.target.data(), evt.target.data('type'));
	});

  $scope.$on('request_fast_ping', function(event, args) {
    $scope.$parent.sendToastData('FastPing', "lancement d'un scan");
    $scope.getFastScan(args.cible);
  });

  $scope.$on('request_arp_scan', function(event, args) {
    $scope.$parent.sendToastData('ARP Scan', "lancement d'un scan");
    $scope.getARPScan(args.cible);
  });

  $scope.$on('request_traceroute_scan', function(event, args) {
    $scope.$parent.sendToastData('Traceroute Scan', "lancement d'un scan");
    $scope.getTracerouteScan();
  });

  $scope.$on('request_profiling_scan', function(event, args) {
    $scope.$parent.sendToastData('Profiling', "lancement d'un scan");
    $scope.getProfilingScan(args.cible);
  });

  $scope.$on('request_services_scan', function(event, args) {
    $scope.$parent.sendToastData('Services', "lancement d'un scan");
    $scope.getServicesScan(args.cible, args.port_start, args.port_end);
  });

  $scope.$on('request_reverse_ptr_scan', function(event, args) {
    $scope.$parent.sendToastData('Reverse PTR', "lancement d'un scan");
    $scope.getReversePTRScan(args.cible);
  })

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