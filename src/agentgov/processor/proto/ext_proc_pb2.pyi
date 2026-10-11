from google.protobuf import struct_pb2 as _struct_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ProcessingRequest(_message.Message):
    __slots__ = ("request_headers", "response_headers", "request_body", "response_body", "request_trailers", "response_trailers", "metadata_context", "observability_mode")
    REQUEST_HEADERS_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_HEADERS_FIELD_NUMBER: _ClassVar[int]
    REQUEST_BODY_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_BODY_FIELD_NUMBER: _ClassVar[int]
    REQUEST_TRAILERS_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_TRAILERS_FIELD_NUMBER: _ClassVar[int]
    METADATA_CONTEXT_FIELD_NUMBER: _ClassVar[int]
    OBSERVABILITY_MODE_FIELD_NUMBER: _ClassVar[int]
    request_headers: HttpHeaders
    response_headers: HttpHeaders
    request_body: HttpBody
    response_body: HttpBody
    request_trailers: HttpTrailers
    response_trailers: HttpTrailers
    metadata_context: Metadata
    observability_mode: bool
    def __init__(self, request_headers: _Optional[_Union[HttpHeaders, _Mapping]] = ..., response_headers: _Optional[_Union[HttpHeaders, _Mapping]] = ..., request_body: _Optional[_Union[HttpBody, _Mapping]] = ..., response_body: _Optional[_Union[HttpBody, _Mapping]] = ..., request_trailers: _Optional[_Union[HttpTrailers, _Mapping]] = ..., response_trailers: _Optional[_Union[HttpTrailers, _Mapping]] = ..., metadata_context: _Optional[_Union[Metadata, _Mapping]] = ..., observability_mode: _Optional[bool] = ...) -> None: ...

class ProcessingResponse(_message.Message):
    __slots__ = ("request_headers", "response_headers", "request_body", "response_body", "request_trailers", "response_trailers", "immediate_response")
    REQUEST_HEADERS_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_HEADERS_FIELD_NUMBER: _ClassVar[int]
    REQUEST_BODY_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_BODY_FIELD_NUMBER: _ClassVar[int]
    REQUEST_TRAILERS_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_TRAILERS_FIELD_NUMBER: _ClassVar[int]
    IMMEDIATE_RESPONSE_FIELD_NUMBER: _ClassVar[int]
    request_headers: HeadersResponse
    response_headers: HeadersResponse
    request_body: BodyResponse
    response_body: BodyResponse
    request_trailers: TrailersResponse
    response_trailers: TrailersResponse
    immediate_response: ImmediateResponse
    def __init__(self, request_headers: _Optional[_Union[HeadersResponse, _Mapping]] = ..., response_headers: _Optional[_Union[HeadersResponse, _Mapping]] = ..., request_body: _Optional[_Union[BodyResponse, _Mapping]] = ..., response_body: _Optional[_Union[BodyResponse, _Mapping]] = ..., request_trailers: _Optional[_Union[TrailersResponse, _Mapping]] = ..., response_trailers: _Optional[_Union[TrailersResponse, _Mapping]] = ..., immediate_response: _Optional[_Union[ImmediateResponse, _Mapping]] = ...) -> None: ...

class HttpHeaders(_message.Message):
    __slots__ = ("headers", "end_of_stream")
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    END_OF_STREAM_FIELD_NUMBER: _ClassVar[int]
    headers: HeaderMap
    end_of_stream: bool
    def __init__(self, headers: _Optional[_Union[HeaderMap, _Mapping]] = ..., end_of_stream: _Optional[bool] = ...) -> None: ...

class HttpBody(_message.Message):
    __slots__ = ("body", "end_of_stream")
    BODY_FIELD_NUMBER: _ClassVar[int]
    END_OF_STREAM_FIELD_NUMBER: _ClassVar[int]
    body: bytes
    end_of_stream: bool
    def __init__(self, body: _Optional[bytes] = ..., end_of_stream: _Optional[bool] = ...) -> None: ...

class HttpTrailers(_message.Message):
    __slots__ = ("trailers",)
    TRAILERS_FIELD_NUMBER: _ClassVar[int]
    trailers: HeaderMap
    def __init__(self, trailers: _Optional[_Union[HeaderMap, _Mapping]] = ...) -> None: ...

class HeadersResponse(_message.Message):
    __slots__ = ("response",)
    RESPONSE_FIELD_NUMBER: _ClassVar[int]
    response: CommonResponse
    def __init__(self, response: _Optional[_Union[CommonResponse, _Mapping]] = ...) -> None: ...

class BodyResponse(_message.Message):
    __slots__ = ("response",)
    RESPONSE_FIELD_NUMBER: _ClassVar[int]
    response: CommonResponse
    def __init__(self, response: _Optional[_Union[CommonResponse, _Mapping]] = ...) -> None: ...

class TrailersResponse(_message.Message):
    __slots__ = ("header_mutation",)
    HEADER_MUTATION_FIELD_NUMBER: _ClassVar[int]
    header_mutation: HeaderMutation
    def __init__(self, header_mutation: _Optional[_Union[HeaderMutation, _Mapping]] = ...) -> None: ...

class CommonResponse(_message.Message):
    __slots__ = ("status", "header_mutation", "body_mutation")
    class ResponseStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        CONTINUE: _ClassVar[CommonResponse.ResponseStatus]
        CONTINUE_AND_REPLACE: _ClassVar[CommonResponse.ResponseStatus]
    CONTINUE: CommonResponse.ResponseStatus
    CONTINUE_AND_REPLACE: CommonResponse.ResponseStatus
    STATUS_FIELD_NUMBER: _ClassVar[int]
    HEADER_MUTATION_FIELD_NUMBER: _ClassVar[int]
    BODY_MUTATION_FIELD_NUMBER: _ClassVar[int]
    status: CommonResponse.ResponseStatus
    header_mutation: HeaderMutation
    body_mutation: BodyMutation
    def __init__(self, status: _Optional[_Union[CommonResponse.ResponseStatus, str]] = ..., header_mutation: _Optional[_Union[HeaderMutation, _Mapping]] = ..., body_mutation: _Optional[_Union[BodyMutation, _Mapping]] = ...) -> None: ...

class BodyMutation(_message.Message):
    __slots__ = ("body", "clear_body", "streamed_response")
    BODY_FIELD_NUMBER: _ClassVar[int]
    CLEAR_BODY_FIELD_NUMBER: _ClassVar[int]
    STREAMED_RESPONSE_FIELD_NUMBER: _ClassVar[int]
    body: bytes
    clear_body: bool
    streamed_response: StreamedBodyResponse
    def __init__(self, body: _Optional[bytes] = ..., clear_body: _Optional[bool] = ..., streamed_response: _Optional[_Union[StreamedBodyResponse, _Mapping]] = ...) -> None: ...

class StreamedBodyResponse(_message.Message):
    __slots__ = ("body", "end_of_stream")
    BODY_FIELD_NUMBER: _ClassVar[int]
    END_OF_STREAM_FIELD_NUMBER: _ClassVar[int]
    body: bytes
    end_of_stream: bool
    def __init__(self, body: _Optional[bytes] = ..., end_of_stream: _Optional[bool] = ...) -> None: ...

class HeaderMutation(_message.Message):
    __slots__ = ("set_headers", "remove_headers")
    SET_HEADERS_FIELD_NUMBER: _ClassVar[int]
    REMOVE_HEADERS_FIELD_NUMBER: _ClassVar[int]
    set_headers: _containers.RepeatedCompositeFieldContainer[HeaderValueOption]
    remove_headers: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, set_headers: _Optional[_Iterable[_Union[HeaderValueOption, _Mapping]]] = ..., remove_headers: _Optional[_Iterable[str]] = ...) -> None: ...

class ImmediateResponse(_message.Message):
    __slots__ = ("status", "headers", "body", "details")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    DETAILS_FIELD_NUMBER: _ClassVar[int]
    status: HttpStatus
    headers: HeaderMutation
    body: bytes
    details: str
    def __init__(self, status: _Optional[_Union[HttpStatus, _Mapping]] = ..., headers: _Optional[_Union[HeaderMutation, _Mapping]] = ..., body: _Optional[bytes] = ..., details: _Optional[str] = ...) -> None: ...

class HttpStatus(_message.Message):
    __slots__ = ("code",)
    CODE_FIELD_NUMBER: _ClassVar[int]
    code: int
    def __init__(self, code: _Optional[int] = ...) -> None: ...

class HeaderValue(_message.Message):
    __slots__ = ("key", "value", "raw_value")
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    RAW_VALUE_FIELD_NUMBER: _ClassVar[int]
    key: str
    value: str
    raw_value: bytes
    def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ..., raw_value: _Optional[bytes] = ...) -> None: ...

class HeaderValueOption(_message.Message):
    __slots__ = ("header", "append_action")
    class HeaderAppendAction(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        APPEND_IF_EXISTS_OR_ADD: _ClassVar[HeaderValueOption.HeaderAppendAction]
        ADD_IF_ABSENT: _ClassVar[HeaderValueOption.HeaderAppendAction]
        OVERWRITE_IF_EXISTS_OR_ADD: _ClassVar[HeaderValueOption.HeaderAppendAction]
        OVERWRITE_IF_EXISTS: _ClassVar[HeaderValueOption.HeaderAppendAction]
    APPEND_IF_EXISTS_OR_ADD: HeaderValueOption.HeaderAppendAction
    ADD_IF_ABSENT: HeaderValueOption.HeaderAppendAction
    OVERWRITE_IF_EXISTS_OR_ADD: HeaderValueOption.HeaderAppendAction
    OVERWRITE_IF_EXISTS: HeaderValueOption.HeaderAppendAction
    HEADER_FIELD_NUMBER: _ClassVar[int]
    APPEND_ACTION_FIELD_NUMBER: _ClassVar[int]
    header: HeaderValue
    append_action: HeaderValueOption.HeaderAppendAction
    def __init__(self, header: _Optional[_Union[HeaderValue, _Mapping]] = ..., append_action: _Optional[_Union[HeaderValueOption.HeaderAppendAction, str]] = ...) -> None: ...

class HeaderMap(_message.Message):
    __slots__ = ("headers",)
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    headers: _containers.RepeatedCompositeFieldContainer[HeaderValue]
    def __init__(self, headers: _Optional[_Iterable[_Union[HeaderValue, _Mapping]]] = ...) -> None: ...

class Metadata(_message.Message):
    __slots__ = ("filter_metadata",)
    class FilterMetadataEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: _struct_pb2.Struct
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ...) -> None: ...
    FILTER_METADATA_FIELD_NUMBER: _ClassVar[int]
    filter_metadata: _containers.MessageMap[str, _struct_pb2.Struct]
    def __init__(self, filter_metadata: _Optional[_Mapping[str, _struct_pb2.Struct]] = ...) -> None: ...
