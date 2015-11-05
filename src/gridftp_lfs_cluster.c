#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <math.h>
#include "gridftp_lfs.h"
#include "lio.h"
#include "interval_skiplist.h"
#include "type_malloc.h"
#include "list.h"
#include "ex3_compare.h"
#include "stack.h"
#include "apr_wrapper.h"

// *************************************************************************
// lfs_cluster_sort - Sort the clusters in descending order.
//    This uses a simple insertion sort.
// *************************************************************************

void lfs_cluster_sort(int *cluster_order, ex_off_t *cluster_weight,
                      int n_clusters)
{
    int i, j;
    ex_off_t weight;

    for (i=0; i<n_clusters; i++) {
        log_printf(5, "START cluster=%d weight=" XOT "\n", i, cluster_weight[i]);
    }

    cluster_order[0] = 0;
    for (i=1; i<n_clusters; i++) {
        cluster_order[i] = i;
        weight = cluster_weight[i];
        j = i;

        while ((j>0) && (cluster_weight[cluster_order[j-1]] < weight)) {
            cluster_order[j] = cluster_order[j-1];
            j--;
        }

        cluster_order[j] = i;
    }

    for (i=0; i<n_clusters; i++) {
        j=cluster_order[i];
        log_printf(5, "END sort=%d cluster=%d weight=" XOT "\n", i, j,
                   cluster_weight[j]);
    }
}

// *************************************************************************
// lfs_cluster - Cluster the given buffers
// *************************************************************************

void lfs_cluster_weight(interval_skiplist_t *written_intervals,
                        lfs_cluster_t *cluster, ex_off_t *cluster_weight,
                        int n_clusters)
{
    interval_skiplist_iter_t it;
    ex_off_t lo, hi;
    lfs_cluster_t *c;
    ex_off_t *interval, weight;
    int i;

    for (i=0; i<n_clusters; i++) {
        c = &(cluster[i]);
        lo = c->lo - 1;
        hi = c->hi + 1;
        it = iter_search_interval_skiplist(written_intervals,
                                            (skiplist_key_t *)&lo,
                                            (skiplist_key_t *)&hi);
        weight = c->hi - c->lo + 1;
        log_printf(5, "i=%d lo=" XOT " hi=" XOT " weight=" XOT "\n",
                    i, c->lo, c->hi, weight);
        while ((interval = next_interval_skiplist(&it)) != NULL) {
            weight += interval[1] - interval[0] + 1;
            log_printf(5, "   i=%d ilo=" XOT " ihi=" XOT " weight=" XOT "\n", i,
                       interval[0], interval[1], weight);
        }
        cluster_weight[i] = weight;
    }
}

// *************************************************************************
// lfs_cluster - Cluster the given buffers
// *************************************************************************

void lfs_cluster(list_t *sorted_buffers, lfs_cluster_t *cluster, 
                    int *n_clusters)
{
    int n;
    list_iter_t it;
    ex_off_t *off;
    ex_off_t next_off;
    Stack_ele_t *ele;
    lfs_cluster_t *c;
    lfs_buffer_t *buf, *prev_buf;

    n = 0;
    it = list_iter_search(sorted_buffers, NULL, 0);
    if (list_next(&it, (list_key_t **)&off, (list_data_t **)&ele) != 0) {
        *n_clusters = 0;
        return;
    }

    buf = get_stack_ele_data(ele);
    next_off = buf->offset + buf->nbytes;
    prev_buf = buf;
    c = &(cluster[n]);
    c->lo = buf->offset;
    push_link(&(c->stack), ele);
    move_to_bottom(&(c->stack));
    log_printf(5, "START offset=" XOT " next=" XOT "\n", buf->offset, next_off);
    while (list_next(&it, (list_key_t **)&off, (list_data_t **)&ele) == 0) {
        buf = get_stack_ele_data(ele);
        if (next_off != buf->offset) { // ** Got a new cluster
            c->hi = prev_buf->offset + prev_buf->nbytes - 1;
            c->len = c->hi - c->lo + 1;
            n++;
            c = &(cluster[n]);
            c->lo = buf->offset;
            move_to_bottom(&(c->stack));
        }

        next_off = buf->offset + buf->nbytes;
        log_printf(5, "offset=" XOT " next=" XOT " n_cluster=%d\n", buf->offset,
                   next_off, n);
        prev_buf = buf;
        insert_link_below(&(c->stack), ele);
    }

    c->hi = prev_buf->offset + prev_buf->nbytes - 1;
    c->len = c->hi - c->lo + 1;
    n++;

    *n_clusters = n;
}


