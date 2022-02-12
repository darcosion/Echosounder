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
    createGraph(response); // on envoie le retour du scan à la fonction de création du graph
  }
};

console.log("lancement d'un scan complet");
window.setInterval(requestAllData,20000);

// ici commence le vis.js
// fonction de génération du graph, prenant un scan complet en entrée :
function createGraph(scan_data) {
  // liste des noeuds
  let nodes = new vis.DataSet([]);

  // ajout de la gateway :
  nodes.add([
    {id: "gateway", label: ('gateway ' + scan_data.local_data[2]), color: 'rgba(62,144,142,0.8)', font: {color: "#a5b0a9"}},
  ]);

  // ajout des entités nmap :
  let i = 0;
  scan_data.scan.forEach(function(nodeAdd) {
    nodes.add([
      {id: i, label: (nodeAdd.IP + '\n' + nodeAdd.OS + '\n' + nodeAdd.mac), color: 'rgba(75,148,140,0.8)', font: {color: "#a5b0a9"}},
    ]);
    i++;
  });

  // liste des chemins
  let edges = new vis.DataSet([]);

  // liaison de toutes les entité nmap avec la gateway :
  for(i; i >= 0; i--) {
    edges.add([
      { from: i, to: "gateway" },
    ]);
  }

  // créaction de l'objet graph
  let container = document.getElementById("mynetwork");
  let data = {
    nodes: nodes,
    edges: edges,
  };
  let options = {
    height: getHeigthWindows80() + "px",
  };
  let network = new vis.Network(container, data, options);
}

// get windows size 80% :
function getHeigthWindows80() {
  let heigth = window.innerHeight;
  heigth = heigth - (heigth/5);
  return heigth.toString();
}