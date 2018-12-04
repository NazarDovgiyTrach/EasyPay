$(function () {
    setPagination();
});

function setPagination() {
    var template = '<button class="btn btn-default" type="button" data-page="{0}">{0}</button>';
    $.get({
        url: '/manager/schedule/unscheduled/pagination/size',
        success: function (data) {
            if (data < 2) {
                $('.ua-pagination').addClass('hide');
                setUnscheduledAddresses(1);
            } else {
                $('#ua-pagination').twbsPagination({
                    first: locales["paginationFirst"],
                    prev: locales["paginationPrevious"],
                    next: locales["paginationNext"],
                    last: locales["paginationLast"],
                    totalPages: data,
                    visiblePages: 10,
                    onPageClick: function (event, page) {
                        setUnscheduledAddresses(page);
                    }
                });
            }


        }
    });
}

function setUnscheduledAddresses(page) {
    var template = '<tr><td>{5}</td><td>{4}</td><td>{3}</td><td>{0}</td><td>{1}</td><td>{2}</td></tr>';

    $.get({
        url: '/manager/schedule/unscheduled/list/page/{0}'.format(page),
        success: function (data) {
            $(".js-unscheduled-addresses").html("");
            $.each(data, function (index, element) {
                var number = page > 1 ? ((page - 1) * 10) + index + 1 : index + 1;
                $(".js-unscheduled-addresses").append(
                    getFullAddressWithTemplate(element, template).format('', '', '', '', '', number)
                );
            });
        }
    });
}