let EchoApp = angular.module('EchoApp', ['ngAnimate']);

EchoApp.controller("ParentCtrl", function($scope) {
  $scope.sendToastData = function(titre, texte) {
    $scope.$broadcast('ToastMessage', {
      'titre' : titre,
      'texte' : texte,
    })
  }
});

EchoApp.controller("leftPanelMenu", function($scope, $rootScope, $http) {
  $scope.showMenu1 = false;
  $scope.showMenu2 = false;
  $scope.showMenu3 = false;

  $scope.cible = "192.168.1.0/24";

  $scope.clickFastPing = function() {
    console.log("emit fast ping request");
    $rootScope.$broadcast('request_fast_ping', {'cible' : $scope.cible});
  }

  $scope.clickScanARP = function() {
    console.log("emit arp scan request");
    $rootScope.$broadcast('request_arp_scan', {'cible' : $scope.cible});
  }

  $scope.clickScanProfiling = function() {
    console.log("emit profiling scan request");
    $rootScope.$broadcast('request_profiling_scan', {'cible' : "10.0.2.15"});
  }
});

EchoApp.controller("rightPanelMenu", function($scope, $rootScope, $http) {
  $scope.showMenu1 = false;
  $scope.showMenu2 = false;
  $scope.showMenu3 = false;

  $scope.nodedata = undefined;

  $scope.$on('updatePanelNodeData', function(event, node, typenode) {
    if(typenode == 'IP') { // on déclenche l'affichage du menu 1 avec les données du node
      console.log("Clic sur un noeud");
      console.log(node);
      $scope.nodedata = node;
      $scope.showMenu1 = true;
      $scope.showMenu2 = false;
      $scope.showMenu3 = false;
      // on demande à angularJS d'actualiser sa vue
      $scope.$apply();
    }
  });

  $scope.exportJSON= function() {
    $rootScope.$broadcast('request_export_json', {});
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
        $scope.createCytoGraph(response.data);
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
        $scope.createCytoGraph(response.data);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('ARP Scan', "erreur Scan : " + error);
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
        // on appel la fonction de création de graphs :
        //$scope.createCytoGraph(response.data);
      },
      // si la requête échoue :
      function(error) {
        $scope.$parent.sendToastData('Profiling Scan', "erreur Scan : " + error);
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
        'text-valign': 'center',
        'text-halign': 'center',
        'opacity' : 1,
        'text-wrap': 'wrap',
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

  $scope.nodes = [];
  $scope.edges = [];

  // fonction de création du graph
  $scope.createCytoGraph = function(scan_data) {
    // ajout de la gateway
    $scope.nodes.push(
      {
        group:'nodes',
        data: {
          id : (scan_data.local_data.gateway_ip + '\n' + scan_data.local_data.gateway_mac),
          label : ("gateway " + scan_data.local_data.gateway_ip + "\n" + scan_data.local_data.gateway_mac),
          type : 'IP',
          data : scan_data.local_data,
        },
      }
    );

    // ajout des entités nmap :
    scan_data.scan.forEach(function(nodeAdd) {
      if(nodeAdd.IP != scan_data.local_data[2]) {
        $scope.nodes.push(
          {
            group:'nodes',
            data: {
              id : (nodeAdd.IP + '\n' + nodeAdd.mac),
              label : (nodeAdd.IP + '\n' + nodeAdd.mac),
              type : 'IP',
              data : nodeAdd,
            },
          }
        );
      }
    });

    // liaison de l'ensemble des entités nmap à la gateway : 
    $scope.nodes.forEach(function(nodeI) {
      if(nodeI.data.id != $scope.nodes[0].data.id) { // on évite de créer un lien entre la gateway et elle-même.
        $scope.edges.push({
              group:'edges',
        data : {
          id : ('link ' + $scope.nodes[0].data.id + " " + nodeI.data.id + " "),
          source : nodeI.data.id,
          target : $scope.nodes[0].data.id,
        }
          });
      }
    });

    // on ajoute l'ensemble des ip au graph
    $scope.cyto.add($scope.nodes);
    // on ajoute l'ensemble des lien au graph
    $scope.cyto.add($scope.edges);
    // on actualise la vue
    $scope.layout = $scope.cyto.layout($scope.options);
    $scope.layout.run();
  };

  // évènement en cas de clic sur un noeud :
	$scope.cyto.on('tap', 'node', function(evt){
		// on envoie au parent le noeud à afficher :
		$scope.$parent.$broadcast("updatePanelNodeData", evt.target.data('data'), evt.target.data('type'));
	});

  $scope.$on('request_fast_ping', function(event, args) {
    console.log("lancement d'un scan complet");
    $scope.$parent.sendToastData('FastPing', "lancement d'un scan");
    $scope.getFastScan(args.cible);
  });

  $scope.$on('request_arp_scan', function(event, args) {
    console.log("lancement d'un scan ARP");
    $scope.$parent.sendToastData('ARP Scan', "lancement d'un scan");
    $scope.getARPScan(args.cible);
  });

  $scope.$on('request_profiling_scan', function(event, args) {
    console.log("lancement d'un scan complet");
    $scope.$parent.sendToastData('Profiling', "lancement d'un scan");
    $scope.getProfilingScan(args.cible);
  });

  $scope.$on('request_export_json', function(event, args) {
    console.log("lancement d'un export JSON");
    $scope.getCytoJSON();
  })

  $scope.getCytoJSON = function() {
    var element = document.createElement('a');
    element.setAttribute('href', 'data:application/json;charset=utf-8,' + encodeURIComponent($scope.cyto.json()));
    element.setAttribute('download', "graph.json");
  
    element.style.display = 'none';
    document.body.appendChild(element);
  
    element.click();
  
    document.body.removeChild(element);
  };
});

angular.element(document).ready(function() {
	angular.bootstrap(document, [ 'EchoApp' ]);
});