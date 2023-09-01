const { createTheatre, getTheatres, getTheatre, updateMovieToTheare: updateMovieToTheare, checkIfMovieInTheatre } = require("../controllers/theatre.controller");
const { verifyIdParam } = require("../middlewares/generic.middlware");
const { validateCreateTheatresBody, verifyAddMoviesToTheatreReqIds } = require("../middlewares/theatre.middlewares");

module.exports =  function(app){
    app.post("/mba/api/v1/theatres",[validateCreateTheatresBody],createTheatre);
    app.get("/mba/api/v1/theatres",[], getTheatres);
    app.get("/mba/api/v1/theatres/:id",[verifyIdParam], getTheatre);
    app.put("/mba/api/v1/theatres/:theatreId/movies/:movieId",[verifyAddMoviesToTheatreReqIds], updateMovieToTheare);
    app.get("/mba/api/v1/theatres/:theatreId/movies/:movieId",[verifyAddMoviesToTheatreReqIds], checkIfMovieInTheatre);

}