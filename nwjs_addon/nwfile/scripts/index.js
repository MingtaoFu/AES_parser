try {
    var addon = require("./addon");
	var DES_data = addon.DES_data;
    var F_computing = addon.F_computing;
    var XOR_computing = addon.XOR_computing;
    var E_computing = addon.E_computing;
    var SBOX_computing = addon.SBOX_computing;
    var file_operation = addon.file_operation;

	var data_key_DOM = document.querySelector("#data-key");
	var data_input_DOM = document.querySelector("#data-input");
	var data_output_DOM = document.querySelector("#data-output");
	var keys_container = document.querySelectorAll("#keys-container div");
	var states_container = document.querySelectorAll("#state-container div");

	document.querySelector("#data-encrypt-btn").addEventListener("click", function() {
		if ($(this).hasClass("disabled")) {
		    return false;
        }

		var key = data_key_DOM.value;
		var input = data_input_DOM.value;
		var ouput = DES_data("-en", key, input);
		//alert(output);
		data_output_DOM.value = ouput.cipher_text;

		var keys = ouput.keys;
		for (var i in keys) {
			keys_container[i].innerText = keys[i];
		}

		var states = ouput.states;
		for (var i in states) {
			states_container[i].innerText = states[i];
		}
	});

	document.querySelector("#F-form").addEventListener("submit", function (e) {
	    e.preventDefault();
	    this.result.value = F_computing(this.R.value, "0000" + this.K.value);
    });

	document.querySelector("#XOR-form").addEventListener("submit", function (e) {
	    e.preventDefault();
	    this.result.value = XOR_computing(this.param1.value, this.param2.value);
    });

	document.querySelector("#E-form").addEventListener("submit", function (e) {
	    e.preventDefault();
	    this.result.value = E_computing(this.r.value);
    });

	document.querySelector("#SBOX-form").addEventListener("submit", function (e) {
	    e.preventDefault();
	    this.result.value = SBOX_computing("0000" + this.input.value);
    });

	var open_path_DOM = document.querySelector("#open-path");
    var save_path_DOM = document.querySelector("#save-path");

    open_path_DOM.addEventListener("input", function () {
        $('#open-file').val("");
    });
    save_path_DOM.addEventListener("input", function () {
        $('#save-file').val("");
    });

    document.querySelector("#open-btn").addEventListener("click", function () {
        var chooser = $('#open-file');
        chooser.unbind('change');
        chooser.change(function(evt) {
            if (!$(this).val()) return;
            open_path_DOM.value = $(this).val();
        });

        chooser.trigger('click');
    });

    document.querySelector("#save-btn").addEventListener("click", function () {
        var chooser = $('#save-file');
        chooser.unbind('change');
        chooser.change(function(evt) {
            if (!$(this).val()) return;
            save_path_DOM.value = $(this).val();
        });

        chooser.trigger('click');
    });

    var file_key_DOM = document.querySelector("#file-key");
    document.querySelector("#file-encrypt-btn").addEventListener("click", function() {
        console.log(11)
        file_operation("-ef", file_key_DOM.value,  open_path_DOM.value, save_path_DOM.value, function (e) {
            alert(e);
        });
    });


} catch (e) {
	document.write(e);
}
	//alert("Exception happened when loading core.");
