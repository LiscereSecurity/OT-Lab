FROM frangoteam/fuxa:latest

# FUXA image used in this lab does not include modbus-serial by default.
# Install it so ModbusTCP devices can be created and used.
RUN npm install --prefix /usr/src/app/FUXA/server modbus-serial@8.0.19
