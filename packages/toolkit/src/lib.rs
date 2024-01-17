// Copyright 2021 Adobe
// All Rights Reserved.
//
// NOTICE: Adobe permits you to use, modify, and distribute this file in
// accordance with the terms of the Adobe license agreement accompanying
// it.

// See https://github.com/rustwasm/wasm-bindgen/issues/2774
#![allow(clippy::unused_unit)]
use c2pa::{AsyncSigner, Ingredient, Manifest};
use js_sys::{Array, Function, Uint8Array, Map};
use log::Level;
use serde::Serialize;
use serde_json::Value;
use serde_wasm_bindgen::Serializer;
use std::panic;
use wasm_bindgen::prelude::*;

mod authoring;
mod error;
mod manifest_store;
mod util;

use authoring::KeyVaultSigner;
use error::Error;
use js_sys::Error as JsSysError;
use js_sys::Reflect;
use manifest_store::{
    get_manifest_store_data, get_manifest_store_data_from_manifest_and_asset_bytes,
};
use util::log_time;

#[wasm_bindgen(typescript_custom_section)]
pub const TS_APPEND_CONTENT: &'static str = r#"
import { ManifestStore } from './types'

export * from './types';

export function getManifestStoreFromArrayBuffer(
    buf: ArrayBuffer,
    mimeType: string
): Promise<ManifestStore>;

export function getManifestStoreFromManifestAndAsset(
    manifestBuffer: ArrayBuffer,
    assetBuffer: ArrayBuffer,
    mimeType: string
): Promise<ManifestStore>;

export type Algorithm = 'ps256' | 'es256' | 'ps384' | 'es384' | 'ps512' | 'es512' | 'ed25519';
export type AssertionLabel = 'stds.exif' | 'stds.schema-org.CreativeWork' | 'c2pa.actions' | string;
export interface SigningInfo {
    alg: Algorithm;
    thumbnail: Uint8Array | undefined;
    thumbnail_format: string | undefined;
    certificates: ArrayBuffer[];
    assertions: Map<AssertionLabel, string> | undefined;
    sign: (buffer: ArrayBuffer) => Promise<ArrayBuffer>;
    timestamp?: (buffer: ArrayBuffer) => Promise<ArrayBuffer>;
    digest: (buffer: ArrayBuffer) => Promise<ArrayBuffer>;
    random: (size: number) => Promise<ArrayBuffer>;
}

export function signAssetBuffer(
    info: SigningInfo,
    buffer: ArrayBuffer,
    mimeType: string
): Promise<ArrayBuffer>
"#;

#[wasm_bindgen(start)]
pub fn run() {
    console_log::init_with_level(Level::Info).unwrap();
    panic::set_hook(Box::new(console_error_panic_hook::hook));
}

/// Creates a JavaScript Error with additional error info
///
/// We can't use wasm-bindgen's `JsError` since it only allows you to set a single message string
#[allow(unused_must_use)]
fn as_js_error(err: Error) -> JsSysError {
    let js_err = JsSysError::new(&err.to_string());
    js_err.set_name(&format!("{:?}", err));

    if let Error::C2pa(c2pa::Error::RemoteManifestUrl(url)) = err {
        js_err.set_name("Toolkit(RemoteManifestUrl)");
        Reflect::set(&js_err, &"url".into(), &url.into());
    }

    js_err
}

#[wasm_bindgen(js_name = getManifestStoreFromArrayBuffer, skip_typescript)]
pub async fn get_manifest_store_from_array_buffer(
    buf: JsValue,
    mime_type: String,
) -> Result<JsValue, JsSysError> {
    log_time("get_manifest_store_from_array_buffer::start");
    let asset: serde_bytes::ByteBuf = serde_wasm_bindgen::from_value(buf)
        .map_err(Error::SerdeInput)
        .map_err(as_js_error)?;
    log_time("get_manifest_store_from_array_buffer::from_bytes");
    let result = get_manifest_store_data(&asset, &mime_type)
        .await
        .map_err(as_js_error)?;
    log_time("get_manifest_store_from_array_buffer::get_result");
    let serializer = Serializer::new().serialize_maps_as_objects(true);
    let js_value = result
        .serialize(&serializer)
        .map_err(|_err| Error::JavaScriptConversion)
        .map_err(as_js_error)?;
    log_time("get_manifest_store_from_array_buffer::javascript_conversion");

    Ok(js_value)
}

#[wasm_bindgen(js_name = getManifestStoreFromManifestAndAsset, skip_typescript)]
pub async fn get_manifest_store_from_manifest_and_asset(
    manifest_buffer: JsValue,
    asset_buffer: JsValue,
    mime_type: String,
) -> Result<JsValue, JsSysError> {
    log_time("get_manifest_store_data_from_manifest_and_asset::start");
    let manifest: serde_bytes::ByteBuf = serde_wasm_bindgen::from_value(manifest_buffer)
        .map_err(Error::SerdeInput)
        .map_err(as_js_error)?;

    let asset: serde_bytes::ByteBuf = serde_wasm_bindgen::from_value(asset_buffer)
        .map_err(Error::SerdeInput)
        .map_err(as_js_error)?;

    log_time("get_manifest_store_data_from_manifest_and_asset::from_bytes");
    let result =
        get_manifest_store_data_from_manifest_and_asset_bytes(&manifest, &mime_type, &asset)
            .await
            .map_err(as_js_error)?;

    let serializer = Serializer::new().serialize_maps_as_objects(true);
    let js_value = result
        .serialize(&serializer)
        .map_err(|_err| Error::JavaScriptConversion)
        .map_err(as_js_error)?;
    log_time("get_manifest_store_data_from_manifest_and_asset::javascript_conversion");

    Ok(js_value)
}

const GENERATOR: &str = "azure_media_provenance/0.1";

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "SigningInfo")]
    pub type SigningInfo;

    #[wasm_bindgen(structural, method, getter)]
    fn alg(this: &SigningInfo) -> String;

    #[wasm_bindgen(structural, method, getter)]
    fn certificates(this: &SigningInfo) -> Array;

    #[wasm_bindgen(structural, method, getter)]
    fn assertions(this: &SigningInfo) -> Option<Map>;

    #[wasm_bindgen(structural, method, getter)]
    fn sign(this: &SigningInfo) -> Function;

    #[wasm_bindgen(structural, method, getter)]
    fn timestamp(this: &SigningInfo) -> Option<Function>;

    #[wasm_bindgen(structural, method, getter)]
    fn digest(this: &SigningInfo) -> Function;

    #[wasm_bindgen(structural, method, getter)]
    fn random(this: &SigningInfo) -> Function;

    #[wasm_bindgen(structural, method, getter)]
    fn thumbnail(this: &SigningInfo) -> Option<Uint8Array>;

    #[wasm_bindgen(structural, method, getter)]
    fn thumbnail_format(this: &SigningInfo) -> String;
}

#[wasm_bindgen(js_name = signAssetBuffer, skip_typescript)]
pub async fn sign_asset_buffer(
    signing_info: &SigningInfo,
    buffer: JsValue,
    mime_type: String,
) -> Result<JsValue, JsSysError> {
    let asset: serde_bytes::ByteBuf = serde_wasm_bindgen::from_value(buffer)
        .map_err(Error::SerdeInput)
        .map_err(as_js_error)?;

    // create a new Manifest
    let mut manifest = Manifest::new(GENERATOR.to_owned());

    if let Some(assertions) = signing_info.assertions() {
        for key in assertions.keys() {
            let key = key.map_err(|_|Error::JavaScriptConversion).map_err(as_js_error)?;
            let value = assertions.get(&key);
            let key = key.as_string().ok_or(Error::JavaScriptConversion).map_err(as_js_error)?;
            let value = value.as_string().ok_or(Error::JavaScriptConversion).map_err(as_js_error)?;
            let value: Value = serde_json::from_str(&value).map_err(|_| Error::JavaScriptConversion).map_err(as_js_error)?;
            manifest.add_labeled_assertion(key, &value).map_err(|_| Error::JavaScriptConversion).map_err(as_js_error)?; 
        }
    };
 
    if let Some(thumbnail) = signing_info.thumbnail() {
        manifest
            .set_thumbnail(signing_info.thumbnail_format(), thumbnail.to_vec())
            .map_err(|x| Error::C2pa(x))
            .map_err(as_js_error)?;
    }

    let source_ingredient = Ingredient::from_memory_async(&mime_type, &asset)
        .await
        .map_err(|e| Error::C2pa(e))
        .map_err(as_js_error)?;
    if source_ingredient.manifest_data().is_some() {
        manifest
            .set_parent(source_ingredient)
            .map_err(|e| Error::C2pa(e))
            .map_err(as_js_error)?;
    }

    let certificates: Vec<Vec<u8>> = signing_info
        .certificates()
        .to_vec()
        .into_iter()
        .map(|x| Uint8Array::new(&x).to_vec())
        .collect();

    let alg = signing_info.alg();
    let signer: Box<dyn AsyncSigner> = Box::new(KeyVaultSigner::new(
        signing_info.sign(),
        signing_info.digest(),
        signing_info.random(),
        signing_info.timestamp(),
        certificates,
        &alg,
    ));
    let data = manifest
        .embed_from_memory_async(&mime_type, &asset, signer.as_ref())
        .await
        .map_err(Error::C2pa)
        .map_err(as_js_error)?;

    let result = Uint8Array::from(&data[..]).into();
    Ok(result)
}
