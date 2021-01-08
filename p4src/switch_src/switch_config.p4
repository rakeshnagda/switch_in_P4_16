/*
Copyright 2013-present Barefoot Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * System global parameters
 */
// #include <v1model.p4>

control process_global_params(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata){
    action deflect_on_drop(bit<1> enable_dod) {
        meta.intrinsic_metadata.deflect_on_drop = enable_dod;
    }
     action set_config_parameters(bit<1> enable_dod) {
        /* read system config parameters and store them in metadata
         * or take appropriate action
         */
        deflect_on_drop(enable_dod);

        /* initialization */
        meta.i2e_metadata.ingress_tstamp = (bit<32>)_ingress_global_tstamp_;
        meta.ingress_metadata.ingress_port = standard_metadata.ingress_port;
        meta.l2_metadata.same_if_check = meta.ingress_metadata.ifindex;
        standard_metadata.egress_spec = INVALID_PORT_ID;
#ifdef SFLOW_ENABLE
        /* use 31 bit random number generator and detect overflow into upper half
         * to decide to take a sample
         */
        //meta.ingress_metadata.sflow_take_sample = rng_uniform.read();
    random<bit<32>>(meta.ingress_metadata.sflow_take_sample, 0, 0x7FFFFFFF);
#endif
    }

    table switch_config_params {
        actions = {
            set_config_parameters();
        }
        size = 1;
    }

    apply {
	/* set up global controls/parameters */
        switch_config_params.apply();
    }

}
