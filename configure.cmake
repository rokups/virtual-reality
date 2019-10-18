include(${VR_SOURCE_DIR}/JSONParser.cmake)
file(READ ${VR_CONFIG} VR_CONFIG_JSON_DATA)
sbeParseJson(VR_CONFIG_JSON VR_CONFIG_JSON_DATA)
set(vr_shared_key "${VR_CONFIG_JSON.shared_key}")
# String embedded into vr-config.h
string(REPLACE "\"" "\\\"" VR_CONFIG_DATA "${VR_CONFIG_JSON_DATA}")
string(REPLACE "\n" "\"\\\n\"" VR_CONFIG_DATA "${VR_CONFIG_DATA}")
configure_file(${VR_SOURCE_DIR}/src/vr-config.h.in ${OUTPUT_BIN_DIRECTORY}/vr-config.h @ONLY)
