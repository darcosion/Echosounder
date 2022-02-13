let epicApp = angular.module('epicApp', []);

epicApp.controller("graphNetwork", function($scope, $rootScope, $http) {
  // fonctions de récupérations de donnée
  $scope.getFastScan = function() {
    let req = {
      method : 'GET',
      url : '/json/fast_scan',
    };
    
    $http(req).then(
      // si la requête passe :
      function(response) {
        console.log(response.data);
        // on appel la fonction de création de graphs :
        $scope.createCytoGraph(response.data);
      },
      // si la requête échoue :
      function(error) {
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
        'color' : '#4ec0e9',
        'background-color' : '#102324', // --fond-color-tres-noir-bleue
        'border-width': 4,
        'content': 'data(id)',
        'text-outline-color': '#080808',
        'text-outline-width' : 3,
        'text-valign': 'center',
        'text-halign': 'center'
      },
    },
    {
      selector: 'edge',
      css: {
        'line-color' : '#4b948c', // --widget-blue3
        'target-arrow-color' : '#5c202a', // --widget-red1
        'curve-style': 'bezier',
        'target-arrow-shape': 'triangle'
      },
    },
  ];
  $scope.cyto.style($scope.styles);

  $scope.nodes = [];
  $scope.edges = [];

  // fonction de création du graph
  $scope.createCytoGraph = function(scan_data) {
    $scope.nodes = [];
    $scope.edges = [];

    // ajout de la gateway
    $scope.nodes.push(
      {
        group:'nodes',
        data: {
          id : "gateway",
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
              id : (nodeAdd.IP),
              type : 'IP',
              data : nodeAdd,
            },
          }
        );
      }
    });

    // liaison de l'ensemble des entités nmap à la gateway : 
    $scope.nodes.forEach(function(nodeI) {
      if(nodeI.data.id != "gateway") {
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

  console.log("lancement d'un scan complet");
  window.setInterval($scope.getFastScan,20000);
});

angular.element(document).ready(function() {
	angular.bootstrap(document, [ 'epicApp' ]);
});