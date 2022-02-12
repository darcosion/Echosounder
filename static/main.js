// fonctionnalités de gestion des appels d'API
let request = new XMLHttpRequest();

// fonction de récupération d'un scan complet
function requestAllData() {
  request.open('GET', "/json/fast_scan"); // on crée la requête
  request.responseType = 'json'; // on spécifie qu'on attends du json
  request.send(); // on envoie la requête
  request.onload = function() {
    let response = request.response;
    console.log(response);
    createCytoGraph(response); // on envoie le retour du scan à la fonction de création du graph
  }
};

console.log("lancement d'un scan complet");
window.setInterval(requestAllData,20000);

/// ici commence le graph
// Fonction de génération du graph basé sur cytoscape (refactoring)
function createCytoGraph(scan_data) {
    let cyto = cytoscape({
		container: document.getElementById('mynetwork')
	});

    let options = {
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

    let styles = [
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

    cyto.style(styles);

    let nodes = [];
    let edges = [];

    // ajout de la gateway
    nodes.push(
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
        nodes.push(
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
    nodes.forEach(function(nodeI) {
        if(nodeI.data.id != "gateway") {
            edges.push({
                group:'edges',
					data : {
						id : ('link ' + nodes[0].data.id + " " + nodeI.data.id + " "),
						source : nodeI.data.id,
						target : nodes[0].data.id,
					}
            });
        }
    });

    // on ajoute l'ensemble des ip au graph
	cyto.add(nodes);
	// on ajoute l'ensemble des lien au graph
	cyto.add(edges);
	// on actualise la vue
	let layout = cyto.layout(options);
	layout.run();
}