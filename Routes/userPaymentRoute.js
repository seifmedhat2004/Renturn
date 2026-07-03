const express =require("express")
const route = express.Router()
const {getAvailableGateWay,chooseGateWay,createCheckout,handlePaymobwebhook,paymentStatus}= require("../Controllers/paymentMethodCotroller")
const { protect } = require("../middlewares/authMiddleware");


route.get("/availablePayment",protect,getAvailableGateWay) //https://renturn.vercel.app/userPayment/availablePayment or http://localhost:5000/api/v1/userPayment/availablePayment
route.post("/choose-gateway",protect,chooseGateWay);//https://renturn.vercel.app/userPayment/choose-gateway or http://localhost:5000/api/v1/userPayment/choose-gateway
route.post("/checkout", protect,createCheckout);//https://renturn.vercel.app/api/v1/userPayment/checkout or http://localhost:5000/api/v1/userPayment/checkout
route.post("/paymob/webhook",protect,handlePaymobwebhook);//https://renturn.vercel.app/userPayment/paymob/webhook
route.get("/response",protect,paymentStatus)//https://renturn.vercel.app/userPayment/paymob/response or http://localhost:5000/api/v1/userPayment/response
module.exports=route;
